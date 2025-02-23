// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package autodiscovery

import (
	"context"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/listeners"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/providers"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/scheduler"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"go.uber.org/atomic"
)

var listenerCandidateIntl = 30 * time.Second

// AutoConfig implements the agent's autodiscovery mechanism.  It is
// responsible to collect integrations configurations from different sources
// and then "schedule" or "unschedule" them by notifying subscribers.  See the
// module README for details.
type AutoConfig struct {
	providers          []*configPoller
	listeners          []listeners.ServiceListener
	listenerCandidates map[string]*listenerCandidate
	listenerRetryStop  chan struct{}
	scheduler          *scheduler.MetaScheduler
	listenerStop       chan struct{}
	healthListening    *health.Handle
	newService         chan listeners.Service
	delService         chan listeners.Service
	store              *store
	cfgMgr             configManager
	m                  sync.RWMutex

	// ranOnce is set to 1 once the AutoConfig has been executed
	ranOnce *atomic.Bool
}

type listenerCandidate struct {
	factory listeners.ServiceListenerFactory
	config  listeners.Config
}

func (l *listenerCandidate) try() (listeners.ServiceListener, error) {
	return l.factory(l.config)
}

// NewAutoConfig creates an AutoConfig instance and starts it.
func NewAutoConfig(scheduler *scheduler.MetaScheduler) *AutoConfig {
	ac := NewAutoConfigNoStart(scheduler)

	// We need to listen to the service channels before anything is sent to them
	go ac.serviceListening()

	return ac
}

// NewAutoConfigNoStart creates an AutoConfig instance.
func NewAutoConfigNoStart(scheduler *scheduler.MetaScheduler) *AutoConfig {
	var cfgMgr configManager
	if util.CcaInAD() {
		cfgMgr = newReconcilingConfigManager()
	} else {
		cfgMgr = newSimpleConfigManager()
	}
	ac := &AutoConfig{
		providers:          make([]*configPoller, 0, 9),
		listenerCandidates: make(map[string]*listenerCandidate),
		listenerRetryStop:  nil, // We'll open it if needed
		listenerStop:       make(chan struct{}),
		healthListening:    health.RegisterLiveness("ad-servicelistening"),
		newService:         make(chan listeners.Service),
		delService:         make(chan listeners.Service),
		store:              newStore(),
		cfgMgr:             cfgMgr,
		scheduler:          scheduler,
		ranOnce:            atomic.NewBool(false),
	}
	return ac
}

// serviceListening is the main management goroutine for services.
// It waits for service events to trigger template resolution and
// checks the tags on existing services are up to date.
func (ac *AutoConfig) serviceListening() {
	ctx, cancel := context.WithCancel(context.Background())

	tagFreshnessTicker := time.NewTicker(15 * time.Second) // we can miss tags for one run
	defer tagFreshnessTicker.Stop()

	for {
		select {
		case <-ac.listenerStop:
			ac.healthListening.Deregister() //nolint:errcheck
			cancel()
			return
		case healthDeadline := <-ac.healthListening.C:
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), healthDeadline)
		case svc := <-ac.newService:
			ac.processNewService(ctx, svc)
		case svc := <-ac.delService:
			ac.processDelService(svc)
		case <-tagFreshnessTicker.C:
			ac.checkTagFreshness(ctx)
		}
	}
}

func (ac *AutoConfig) checkTagFreshness(ctx context.Context) {
	// check if services tags are up to date
	var servicesToRefresh []listeners.Service
	for _, service := range ac.store.getServices() {
		previousHash := ac.store.getTagsHashForService(service.GetTaggerEntity())
		currentHash := tagger.GetEntityHash(service.GetTaggerEntity(), tagger.ChecksCardinality)
		// Since an empty hash is a valid value, and we are not able to differentiate
		// an empty tagger or store with an empty value.
		// So we only look at the difference between current and previous
		if currentHash != previousHash {
			ac.store.setTagsHashForService(service.GetTaggerEntity(), currentHash)
			servicesToRefresh = append(servicesToRefresh, service)
		}
	}
	for _, service := range servicesToRefresh {
		log.Debugf("Tags changed for service %s, rescheduling associated checks if any", service.GetTaggerEntity())
		ac.processDelService(service)
		ac.processNewService(ctx, service)
	}
}

// Stop just shuts down AutoConfig in a clean way.
// AutoConfig is not supposed to be restarted, so this is expected
// to be called only once at program exit.
func (ac *AutoConfig) Stop() {
	ac.m.Lock()
	defer ac.m.Unlock()

	// stop polled config providers
	for _, pd := range ac.providers {
		pd.stop()
	}

	// stop the service listener
	ac.listenerStop <- struct{}{}

	// stop the meta scheduler
	ac.scheduler.Stop()

	// stop the listener retry logic if running
	if ac.listenerRetryStop != nil {
		ac.listenerRetryStop <- struct{}{}
	}

	// stop all the listeners
	for _, l := range ac.listeners {
		l.Stop()
	}
}

// AddConfigProvider adds a new configuration provider to AutoConfig.
// Callers must pass a flag to indicate whether the configuration provider
// expects to be polled and at which interval or it's fine for it to be invoked only once in the
// Agent lifetime.
// If the config provider is polled, the routine is scheduled right away
func (ac *AutoConfig) AddConfigProvider(provider providers.ConfigProvider, shouldPoll bool, pollInterval time.Duration) {
	ac.m.Lock()
	defer ac.m.Unlock()

	for _, pd := range ac.providers {
		if pd.provider == provider {
			// we already know this configuration provider, don't do anything
			log.Warnf("Provider %s was already added, skipping...", provider)
			return
		}
	}

	pd := newConfigPoller(provider, shouldPoll, pollInterval)
	ac.providers = append(ac.providers, pd)
	pd.start(ac)
}

// LoadAndRun loads all of the integration configs it can find
// and schedules them. Should always be run once so providers
// that don't need polling will be queried at least once
func (ac *AutoConfig) LoadAndRun() {
	scheduleAll := ac.getAllConfigs()
	ac.applyChanges(scheduleAll)
	ac.ranOnce.Store(true)
	log.Debug("LoadAndRun done.")
}

// ForceRanOnceFlag sets the ranOnce flag.  This is used for testing other
// components that depend on this value.
func (ac *AutoConfig) ForceRanOnceFlag() {
	ac.ranOnce.Store(true)
}

// HasRunOnce returns true if the AutoConfig has ran once.
func (ac *AutoConfig) HasRunOnce() bool {
	if ac == nil {
		return false
	}
	return ac.ranOnce.Load()
}

// GetAllConfigs queries all the providers and returns all the integration
// configurations found, resolving the ones it can
func (ac *AutoConfig) GetAllConfigs() []integration.Config {
	return ac.getAllConfigs().schedule
}

// getAllConfigs queries all the providers and returns all the integration
// configurations found, resolving the ones it can, and returns a configChanges to
// schedule all of them.
func (ac *AutoConfig) getAllConfigs() configChanges {
	changes := configChanges{}

	for _, pd := range ac.providers {
		cfgs, err := pd.provider.Collect(context.TODO())
		if err != nil {
			log.Debugf("Unexpected error returned when collecting configurations from provider %v: %v", pd.provider, err)
		}

		if fileConfPd, ok := pd.provider.(*providers.FileConfigProvider); ok {
			var goodConfs []integration.Config
			for _, cfg := range cfgs {
				// JMX checks can have 2 YAML files: one containing the metrics to collect, one containing the
				// instance configuration
				// If the file provider finds any of these metric YAMLs, we store them in a map for future access
				if cfg.MetricConfig != nil {
					// We don't want to save metric files, it's enough to store them in the map
					ac.store.setJMXMetricsForConfigName(cfg.Name, cfg.MetricConfig)
					continue
				}

				goodConfs = append(goodConfs, cfg)

				// Clear any old errors if a valid config file is found
				errorStats.removeConfigError(cfg.Name)
			}

			// Grab any errors that occurred when reading the YAML file
			for name, e := range fileConfPd.Errors {
				errorStats.setConfigError(name, e)
			}

			cfgs = goodConfs
		}
		// Store all raw configs in the provider
		pd.overwriteConfigs(cfgs)

		// resolve configs if needed
		for _, config := range cfgs {
			config.Provider = pd.provider.String()
			changes.merge(ac.processNewConfig(config))
		}
	}

	return changes
}

// processNewConfig store (in template cache) and resolves a given config,
// returning the changes to be made.
func (ac *AutoConfig) processNewConfig(config integration.Config) configChanges {
	// add default metrics to collect to JMX checks
	if check.CollectDefaultMetrics(config) {
		metrics := ac.store.getJMXMetricsForConfigName(config.Name)
		if len(metrics) == 0 {
			log.Infof("%s doesn't have an additional metric configuration file: not collecting default metrics", config.Name)
		} else if err := config.AddMetrics(metrics); err != nil {
			log.Infof("Unable to add default metrics to collect to %s check: %s", config.Name, err)
		}
	}

	return ac.cfgMgr.processNewConfig(config)
}

// AddListeners tries to initialise the listeners listed in the given configs. A first
// try is done synchronously. If a listener fails with a ErrWillRetry, the initialization
// will be re-triggered later until success or ErrPermaFail.
func (ac *AutoConfig) AddListeners(listenerConfigs []config.Listeners) {
	ac.addListenerCandidates(listenerConfigs)
	remaining := ac.initListenerCandidates()
	if remaining == false {
		return
	}

	// Start the retry logic if we have remaining candidates and it is not already running
	ac.m.Lock()
	defer ac.m.Unlock()
	if ac.listenerRetryStop == nil {
		ac.listenerRetryStop = make(chan struct{})
		go ac.retryListenerCandidates()
	}
}

func (ac *AutoConfig) addListenerCandidates(listenerConfigs []config.Listeners) {
	ac.m.Lock()
	defer ac.m.Unlock()

	for _, c := range listenerConfigs {
		factory, ok := listeners.ServiceListenerFactories[c.Name]
		if !ok {
			// Factory has not been registered.
			log.Warnf("Listener %s was not registered", c.Name)
			continue
		}
		log.Debugf("Listener %s was registered", c.Name)
		ac.listenerCandidates[c.Name] = &listenerCandidate{factory: factory, config: &c}
	}
}

func (ac *AutoConfig) initListenerCandidates() bool {
	ac.m.Lock()
	defer ac.m.Unlock()

	for name, candidate := range ac.listenerCandidates {
		listener, err := candidate.try()
		switch {
		case err == nil:
			// Init successful, let's start listening
			log.Infof("%s listener successfully started", name)
			ac.listeners = append(ac.listeners, listener)
			listener.Listen(ac.newService, ac.delService)
			delete(ac.listenerCandidates, name)
		case retry.IsErrWillRetry(err):
			// Log an info and keep in candidates
			log.Infof("%s listener cannot start, will retry: %s", name, err)
		default:
			// Log an error and remove from candidates
			log.Errorf("%s listener cannot start: %s", name, err)
			delete(ac.listenerCandidates, name)
		}
	}

	return len(ac.listenerCandidates) > 0
}

func (ac *AutoConfig) retryListenerCandidates() {
	retryTicker := time.NewTicker(listenerCandidateIntl)
	defer func() {
		// Stop ticker
		retryTicker.Stop()
		// Cleanup channel before exiting so that we can re-start the routine later
		ac.m.Lock()
		defer ac.m.Unlock()
		close(ac.listenerRetryStop)
		ac.listenerRetryStop = nil
	}()

	for {
		select {
		case <-ac.listenerRetryStop:
			return
		case <-retryTicker.C:
			remaining := ac.initListenerCandidates()
			if !remaining {
				return
			}
		}
	}
}

// AddScheduler allows to register a new scheduler to receive configurations.
// Previously scheduled configurations that have not subsequently been
// unscheduled can be replayed with the replayConfigs flag.
func (ac *AutoConfig) AddScheduler(name string, s scheduler.Scheduler, replayConfigs bool) {
	ac.m.Lock()
	defer ac.m.Unlock()

	ac.scheduler.Register(name, s, replayConfigs)
}

// RemoveScheduler allows to remove a scheduler from the AD system.
func (ac *AutoConfig) RemoveScheduler(name string) {
	ac.scheduler.Deregister(name)
}

func (ac *AutoConfig) processRemovedConfigs(configs []integration.Config) {
	changes := ac.cfgMgr.processDelConfigs(configs)
	ac.applyChanges(changes)
}

// MapOverLoadedConfigs calls the given function with the map of all
// loaded configs (those that would be returned from LoadedConfigs).
//
// This is done with the config store locked, so callers should perform minimal
// work within f.
func (ac *AutoConfig) MapOverLoadedConfigs(f func(map[string]integration.Config)) {
	if ac == nil || ac.store == nil {
		log.Error("Autoconfig store not initialized")
		f(map[string]integration.Config{})
		return
	}
	ac.cfgMgr.mapOverLoadedConfigs(f)
}

// LoadedConfigs returns a slice of all loaded configs.  Loaded configs are non-template
// configs, either as received from a config provider or as resolved from a template and
// a service.  They do not include service configs.
//
// The returned slice is freshly created and will not be modified after return.
func (ac *AutoConfig) LoadedConfigs() []integration.Config {
	var configs []integration.Config
	ac.cfgMgr.mapOverLoadedConfigs(func(loadedConfigs map[string]integration.Config) {
		configs = make([]integration.Config, 0, len(loadedConfigs))
		for _, c := range loadedConfigs {
			configs = append(configs, c)
		}
	})

	return configs
}

// GetUnresolvedTemplates returns all templates in the cache, in their unresolved
// state.
func (ac *AutoConfig) GetUnresolvedTemplates() map[string][]integration.Config {
	return ac.store.templateCache.getUnresolvedTemplates()
}

// processNewService takes a service, tries to match it against templates and
// triggers scheduling events if it finds a valid config for it.
func (ac *AutoConfig) processNewService(ctx context.Context, svc listeners.Service) {
	// in any case, register the service and store its tag hash
	ac.store.setServiceForEntity(svc, svc.GetServiceID())
	ac.store.setTagsHashForService(
		svc.GetTaggerEntity(),
		tagger.GetEntityHash(svc.GetTaggerEntity(), tagger.ChecksCardinality),
	)

	// get all the templates matching service identifiers
	ADIdentifiers, err := svc.GetADIdentifiers(ctx)
	if err != nil {
		log.Errorf("Failed to get AD identifiers for service %s, it will not be monitored - %s", svc.GetServiceID(), err)
		return
	}

	changes := ac.cfgMgr.processNewService(ADIdentifiers, svc)

	if !util.CcaInAD() {
		// schedule a "service config" for logs-agent's benefit
		changes.scheduleConfig(integration.Config{
			LogsConfig:      integration.Data{},
			ServiceID:       svc.GetServiceID(),
			TaggerEntity:    svc.GetTaggerEntity(),
			MetricsExcluded: svc.HasFilter(containers.MetricsFilter),
			LogsExcluded:    svc.HasFilter(containers.LogsFilter),
		})
	}

	ac.applyChanges(changes)
}

// processDelService takes a service, stops its associated checks, and updates the cache
func (ac *AutoConfig) processDelService(svc listeners.Service) {
	ac.store.removeServiceForEntity(svc.GetServiceID())
	changes := ac.cfgMgr.processDelService(svc)
	ac.store.removeTagsHashForService(svc.GetTaggerEntity())

	if !util.CcaInAD() {
		// unschedule the "service config"
		changes.unscheduleConfig(integration.Config{
			LogsConfig:      integration.Data{},
			ServiceID:       svc.GetServiceID(),
			TaggerEntity:    svc.GetTaggerEntity(),
			MetricsExcluded: svc.HasFilter(containers.MetricsFilter),
			LogsExcluded:    svc.HasFilter(containers.LogsFilter),
		})
	}

	ac.applyChanges(changes)
}

// GetAutodiscoveryErrors fetches AD errors from each ConfigProvider.  The
// resulting data structure maps provider name to resource name to a set of
// unique error messages.  The resource names do not match other identifiers
// and are only intended for display in diagnostic tools like `agent status`.
func (ac *AutoConfig) GetAutodiscoveryErrors() map[string]map[string]providers.ErrorMsgSet {
	errors := map[string]map[string]providers.ErrorMsgSet{}
	for _, pd := range ac.providers {
		configErrors := pd.provider.GetConfigErrors()
		if len(configErrors) > 0 {
			errors[pd.provider.String()] = configErrors
		}
	}
	return errors
}

// applyChanges applies a configChanges object. This always unschedules first.
func (ac *AutoConfig) applyChanges(changes configChanges) {
	if len(changes.unschedule) > 0 {
		ac.scheduler.Unschedule(changes.unschedule)
	}
	if len(changes.schedule) > 0 {
		ac.scheduler.Schedule(changes.schedule)
	}
}

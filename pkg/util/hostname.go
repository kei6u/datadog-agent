// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !serverless
// +build !serverless

package util

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/DataDog/datadog-agent/pkg/metadata/inventories"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/ec2"
	"github.com/DataDog/datadog-agent/pkg/util/ecs"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/DataDog/datadog-agent/pkg/util/hostname/validate"
)

var (
	hostnameExpvars  = expvar.NewMap("hostname")
	hostnameProvider = expvar.String{}
	hostnameErrors   = expvar.Map{}
)

func init() {
	hostnameErrors.Init()
	hostnameExpvars.Set("provider", &hostnameProvider)
	hostnameExpvars.Set("errors", &hostnameErrors)
}

// Fqdn returns the FQDN for the host if any
func Fqdn(hostname string) string {
	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			return hosts[0]
		}
	}
	return hostname
}

func setHostnameProvider(name string) {
	hostnameProvider.Set(name)
	inventories.SetAgentMetadata(inventories.AgentHostnameSource, name)
}

// isOSHostnameUsable returns `false` if it has the certainty that the agent is running
// in a non-root UTS namespace because in that case, the OS hostname characterizes the
// identity of the agent container and not the one of the nodes it is running on.
// There can be some cases where the agent is running in a non-root UTS namespace that are
// not detected by this function (systemd-nspawn containers, manual `unshare -u`…)
// In those uncertain cases, it returns `true`.
func isOSHostnameUsable(ctx context.Context) (osHostnameUsable bool) {
	// If the agent is not containerized, just skip all this detection logic
	if !config.IsContainerized() {
		return true
	}

	// Check UTS namespace from docker
	utsMode, err := GetAgentUTSMode(ctx)
	if err == nil && (utsMode != containers.HostUTSMode && utsMode != containers.UnknownUTSMode) {
		log.Debug("Agent is running in a docker container without host UTS mode: OS-provided hostnames cannot be used for hostname resolution.")
		return false
	}

	// Check hostNetwork from kubernetes
	// because kubernetes sets UTS namespace to host if and only if hostNetwork = true:
	// https://github.com/kubernetes/kubernetes/blob/cf16e4988f58a5b816385898271e70c3346b9651/pkg/kubelet/dockershim/security_context.go#L203-L205
	if config.IsFeaturePresent(config.Kubernetes) {
		hostNetwork, err := isAgentKubeHostNetwork()
		if err == nil && !hostNetwork {
			log.Debug("Agent is running in a POD without hostNetwork: OS-provided hostnames cannot be used for hostname resolution.")
			return false
		}
	}

	return true
}

// GetHostname retrieves the host name from GetHostnameData
func GetHostname(ctx context.Context) (string, error) {
	hostnameData, err := GetHostnameData(ctx)
	return hostnameData.Hostname, err
}

// HostnameProviderConfiguration is the key for the hostname provider associated to datadog.yaml
const HostnameProviderConfiguration = "configuration"

// HostnameData contains hostname and the hostname provider
type HostnameData struct {
	Hostname string
	Provider string
}

// saveHostnameData creates a HostnameData struct, saves it in the cache under cacheHostnameKey
// and calls setHostnameProvider with the provider if it is not empty.
func saveHostnameData(cacheHostnameKey string, hostname string, provider string) HostnameData {
	hostnameData := HostnameData{Hostname: hostname, Provider: provider}
	cache.Cache.Set(cacheHostnameKey, hostnameData, cache.NoExpiration)
	if provider != "" {
		setHostnameProvider(provider)
	}
	return hostnameData
}

func saveAndValidateHostnameData(ctx context.Context, cacheHostnameKey string, hostname string, provider string) HostnameData {
	hostnameData := saveHostnameData(cacheHostnameKey, hostname, HostnameProviderConfiguration)
	if !isHostnameCanonicalForIntake(ctx, hostname) && !config.Datadog.GetBool("hostname_force_config_as_canonical") {
		log.Warnf(
			"Hostname '%s' defined in configuration will not be used as the in-app hostname. "+
				"For more information: https://dtdg.co/agent-hostname-force-config-as-canonical",
			hostname,
		)
	}

	return hostnameData
}

// GetHostnameData retrieves the host name for the Agent and hostname provider, trying to query these
// environments/api, in order:
// * Config (`hostname')
// * Config (`hostname_file')
// * GCE
// * Docker
// * kubernetes
// * os
// * EC2
func GetHostnameData(ctx context.Context) (HostnameData, error) {
	cacheHostnameKey := cache.BuildAgentKey("hostname")
	if cacheHostname, found := cache.Cache.Get(cacheHostnameKey); found {
		return cacheHostname.(HostnameData), nil
	}

	var hostName string
	var err error
	var provider string

	// Try the name provided in the configuration file
	configName := config.Datadog.GetString("hostname")
	err = validate.ValidHostname(configName)
	if err == nil {
		return saveAndValidateHostnameData(
			ctx,
			cacheHostnameKey,
			configName,
			HostnameProviderConfiguration,
		), nil
	}

	expErr := new(expvar.String)
	expErr.Set(err.Error())
	hostnameErrors.Set("configuration/environment", expErr)

	log.Debugf("Unable to get the hostname from the config file: %s", err)

	// Try `hostname_file` config option next
	configHostnameFilepath := config.Datadog.GetString("hostname_file")
	if configHostnameFilepath != "" {
		log.Debug("GetHostname trying `hostname_file` config option...")
		if fileHostnameProvider := hostname.GetProvider("file"); fileHostnameProvider != nil {
			if hostname, err := fileHostnameProvider(
				ctx,
				map[string]interface{}{
					"filename": configHostnameFilepath,
				},
			); err == nil {
				return saveAndValidateHostnameData(ctx, cacheHostnameKey, hostname, "file"), nil
			}

			expErr := new(expvar.String)
			expErr.Set(err.Error())
			hostnameErrors.Set("configuration/environment", expErr)
			log.Debugf("Unable to get hostname from file '%s': %s", configHostnameFilepath, err)
		}
	}

	log.Debug("Trying to determine a reliable host name automatically...")

	// If fargate we strip the hostname
	if fargate.IsFargateInstance(ctx) {
		hostnameData := saveHostnameData(cacheHostnameKey, "", "")
		return hostnameData, nil
	}

	// GCE metadata
	log.Debug("GetHostname trying GCE metadata...")
	if getGCEHostname := hostname.GetProvider("gce"); getGCEHostname != nil {
		gceName, err := getGCEHostname(ctx, nil)
		if err == nil {
			hostnameData := saveHostnameData(cacheHostnameKey, gceName, "gce")
			return hostnameData, err
		}
		expErr := new(expvar.String)
		expErr.Set(err.Error())
		hostnameErrors.Set("gce", expErr)
		log.Debug("Unable to get hostname from GCE: ", err)
	}

	// FQDN
	var fqdn string
	canUseOSHostname := isOSHostnameUsable(ctx)
	if canUseOSHostname {
		log.Debug("GetHostname trying FQDN/`hostname -f`...")
		fqdn, err = getSystemFQDN()
		if config.Datadog.GetBool("hostname_fqdn") && err == nil {
			hostName = fqdn
			provider = "fqdn"
		} else {
			if err != nil {
				expErr := new(expvar.String)
				expErr.Set(err.Error())
				hostnameErrors.Set("fqdn", expErr)
			}
			log.Debug("Unable to get FQDN from system: ", err)
		}
	}

	if config.IsContainerized() {
		containerName := getContainerHostname(ctx)
		if containerName != "" {
			hostName = containerName
			provider = "container"
		} else {
			expErr := new(expvar.String)
			expErr.Set("Unable to get hostname from container API")
			hostnameErrors.Set("container", expErr)
		}
	}

	if canUseOSHostname && hostName == "" {
		// os
		log.Debug("GetHostname trying os...")
		systemName, err := os.Hostname()
		if err == nil {
			hostName = systemName
			provider = "os"
		} else {
			expErr := new(expvar.String)
			expErr.Set(err.Error())
			hostnameErrors.Set("os", expErr)
			log.Debug("Unable to get hostname from OS: ", err)
		}
	}

	// at this point we've either the hostname from the os or an empty string
	// ------------------------

	// We use the instance id if we're on an ECS cluster or we're on EC2 and the hostname is one of the default ones
	// or ec2_prioritize_instance_id_as_hostname is set to true
	prioritizeEC2Hostname := config.Datadog.GetBool("ec2_prioritize_instance_id_as_hostname")
	if getEC2Hostname := hostname.GetProvider("ec2"); getEC2Hostname != nil {
		log.Debug("GetHostname trying EC2 metadata...")

		if ecs.IsECSInstance() || ec2.IsDefaultHostname(hostName) || prioritizeEC2Hostname {
			ec2Hostname, err := getValidEC2Hostname(ctx, getEC2Hostname)

			if err == nil {
				if prioritizeEC2Hostname {
					return saveHostnameData(cacheHostnameKey, ec2Hostname, "aws"), nil
				}

				hostName = ec2Hostname
				provider = "aws"
			} else {
				expErr := new(expvar.String)
				expErr.Set(err.Error())
				hostnameErrors.Set("aws", expErr)
				log.Debug(err)
			}
		} else {
			err := fmt.Errorf("not retrieving hostname from AWS: the host is not an ECS instance and other providers already retrieve non-default hostnames")
			log.Debug(err.Error())
			expErr := new(expvar.String)
			expErr.Set(err.Error())
			hostnameErrors.Set("aws", expErr)

			// Display a message when enabling `ec2_use_windows_prefix_detection` would make the hostname resolution change.
			if ec2.IsWindowsDefaultHostname(hostName) {
				// As we are in the else clause `ec2.IsDefaultHostname(hostName)` is false. If `ec2.IsWindowsDefaultHostname(hostName)`
				// is `true` that means `ec2_use_windows_prefix_detection` is set to false.
				ec2Hostname, err := getValidEC2Hostname(ctx, getEC2Hostname)

				// Check if we get a valid hostname when enabling `ec2_use_windows_prefix_detection` and the hostnames are different.
				if err == nil && ec2Hostname != hostName {
					// REMOVEME: This should be removed if/when the default `ec2_use_windows_prefix_detection` is set to true
					log.Infof("The agent resolved your hostname as '%s'. You may want to use the EC2 instance-id ('%s') for the in-app hostname."+
						" For more information: https://docs.datadoghq.com/ec2-use-win-prefix-detection", hostName, ec2Hostname)
				}
			}
		}
	} else if prioritizeEC2Hostname {
		expErr := new(expvar.String)
		expErr.Set("ec2 hostname provider is not enabled despite ec2_prioritize_instance_id_as_hostname being set to true")
		hostnameErrors.Set("forced EC2 hostname", expErr)
	}

	if getAzureHostname := hostname.GetProvider("azure"); getAzureHostname != nil {
		log.Debug("GetHostname trying Azure metadata...")

		azureHostname, err := getAzureHostname(ctx, nil)
		if err == nil {
			hostName = azureHostname
			provider = "azure"
		} else {
			expErr := new(expvar.String)
			expErr.Set(err.Error())
			hostnameErrors.Set("azure", expErr)
			log.Debugf("unable to get hostname from Azure: %s", err)
		}
	}

	h, err := os.Hostname()
	// We have a FQDN not equals to the resolved hostname, and the configuration
	// field `hostname_fqdn` isn't set -> we display a warning message about
	// the future behavior
	if err == nil && !config.Datadog.GetBool("hostname_fqdn") && fqdn != "" && hostName == h && h != fqdn {
		if runtime.GOOS != "windows" {
			// REMOVEME: This should be removed when the default `hostname_fqdn` is set to true
			log.Warnf("DEPRECATION NOTICE: The agent resolved your hostname as '%s'. However in a future version, it will be resolved as '%s' by default. To enable the future behavior, please enable the `hostname_fqdn` flag in the configuration. For more information: https://dtdg.co/flag-hostname-fqdn", h, fqdn)
		} else { // OS is Windows
			log.Warnf("The agent resolved your hostname as '%s', and will be reported this way to maintain compatibility with version 5. To enable reporting as '%s', please enable the `hostname_fqdn` flag in the configuration. For more information: https://dtdg.co/flag-hostname-fqdn", h, fqdn)
		}
	}

	// If at this point we don't have a name, bail out
	if hostName == "" {
		err = fmt.Errorf("unable to reliably determine the host name. You can define one in the agent config file or in your hosts file")
		expErr := new(expvar.String)
		expErr.Set(err.Error())
		hostnameErrors.Set("all", expErr)
		return HostnameData{}, err
	}

	// we have a hostname, cache it and return it

	hostnameData := saveHostnameData(cacheHostnameKey, hostName, provider)
	return hostnameData, nil
}

// isHostnameCanonicalForIntake returns true if the intake will use the hostname as canonical hostname.
func isHostnameCanonicalForIntake(ctx context.Context, hostname string) bool {
	// Intake uses instance id for ec2 default hostname except for Windows.
	if ec2.IsDefaultHostnameForIntake(hostname) {
		_, err := ec2.GetInstanceID(ctx)
		return err != nil
	}
	return true
}

// getValidEC2Hostname gets a valid EC2 hostname
// Returns (hostname, error)
func getValidEC2Hostname(ctx context.Context, ec2Provider hostname.Provider) (string, error) {
	instanceID, err := ec2Provider(ctx, nil)
	if err == nil {
		err = validate.ValidHostname(instanceID)
		if err == nil {
			return instanceID, nil
		}
		return "", fmt.Errorf("EC2 instance ID is not a valid hostname: %s", err)
	}
	return "", fmt.Errorf("Unable to determine hostname from EC2: %s", err)
}

// NormalizeHost applies a liberal policy on host names.
func NormalizeHost(host string) (string, error) {
	var buf bytes.Buffer

	// hosts longer than 253 characters are illegal
	if len(host) > 253 {
		return "", fmt.Errorf("hostname is too long, should contain less than 253 characters")
	}

	for _, r := range host {
		switch r {
		// has null rune just toss the whole thing
		case '\x00':
			return "", fmt.Errorf("hostname cannot contain null character")
		// drop these characters entirely
		case '\n', '\r', '\t':
			continue
		// replace characters that are generally used for xss with '-'
		case '>', '<':
			buf.WriteByte('-')
		default:
			buf.WriteRune(r)
		}
	}

	return buf.String(), nil
}

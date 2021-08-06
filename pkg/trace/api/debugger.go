// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package api

import (
	"fmt"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/trace/info"
	"github.com/DataDog/datadog-agent/pkg/trace/logutil"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
)

const (
	// logsIntakeURLTemplate specifies the template for obtaining the profiling URL along with the site.
	logsIntakeURLTemplate = "https://http-intake.logs.%s/v1/input"
	// logsIntakeDefaultURL specifies the default intake API URL.
	logsIntakeDefaultURL = "https://http-intake.logs.datadoghq.com/v1/input"

	// debuggerRequestMetricsPrefix is the prefix for the following debugger metric names.
	debuggerRequestMetricsPrefix       = "datadog.trace_agent.debugger."
	debuggerRequestCountMetricsName    = debuggerRequestMetricsPrefix + "proxy_request"
	debuggerRequestDurationMetricsName = debuggerRequestMetricsPrefix + "proxy_request_duration_ms"
	debuggerRequestErrorMetricsName    = debuggerRequestMetricsPrefix + "proxy_request_error"
)

// debuggerProxyHandler returns an http.Handler proxying requests to the logs intake. If the logs intake url cannot be
// parsed, the returned handler will always return http.StatusInternalServerError with a clarifying message.
func (r *HTTPReceiver) debuggerProxyHandler() http.Handler {
	tags := fmt.Sprintf("host:%s,default_env:%s,agent_version:%s", r.conf.Hostname, r.conf.DefaultEnv, info.Version)
	orch := r.conf.FargateOrchestrator
	if orch != fargate.Unknown {
		tag := fmt.Sprintf("orchestrator:fargate_%s", strings.ToLower(string(orch)))
		tags = tags + "," + tag
	}
	intake := logsIntakeDefaultURL
	if v := config.Datadog.GetString("apm_config.debugger_dd_url"); v != "" {
		intake = v
	} else if site := config.Datadog.GetString("site"); site != "" {
		intake = fmt.Sprintf(logsIntakeURLTemplate, site)
	}
	target, err := url.Parse(intake)
	if err != nil {
		return debuggerErrorHandler(fmt.Errorf("error parsing snapshot intake URL %s: %v", intake, err))
	}
	return newDebuggerProxy(r.conf.NewHTTPTransport(), target, r.conf.APIKey(), tags)
}

// debuggerErrorHandler always returns http.StatusInternalServerError with a clarifying message.
func debuggerErrorHandler(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		msg := fmt.Sprintf("Debugger Proxy is OFF: %v", err)
		http.Error(w, msg, http.StatusInternalServerError)
	})
}

// newDebuggerProxy returns a new httputil.ReverseProxy proxying and augmenting requests with headers containing the tags.
func newDebuggerProxy(rt http.RoundTripper, target *url.URL, key string, tags string) *httputil.ReverseProxy {
	logger := logutil.NewThrottled(5, 10*time.Second) // limit to 5 messages every 10 seconds
	return &httputil.ReverseProxy{
		Director:  headerDecoratorDirector(tags, "debugger"),
		ErrorLog:  stdlog.New(logger, "debugger.Proxy: ", 0),
		Transport: &roundTripper{target, key, rt},
	}
}

// roundTripper sends HTTP requests to a defined target url. It also sets the API keys in the headers.
type roundTripper struct {
	url *url.URL
	key string
	rt  http.RoundTripper
}

func (r *roundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	now := time.Now()
	defer func() {
		tags := []string{"path:" + req.URL.Path}
		metrics.Count(debuggerRequestCountMetricsName, 1, tags, 1)
		metrics.Timing(debuggerRequestDurationMetricsName, time.Since(now), tags, 1)
		if err != nil {
			tags = append(tags, fmt.Sprintf("error:%s", fmt.Sprintf("%T", err)))
			metrics.Count(debuggerRequestErrorMetricsName, 1, tags, 1)
		}
	}()
	req.Header.Set("DD-API-KEY", r.key)
	req.URL = r.url
	req.Host = r.url.Host
	return r.rt.RoundTrip(req)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

//go:build otlp && test
// +build otlp,test

package otlp

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/otlp/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsEnabled(t *testing.T) {
	tests := []struct {
		path    string
		enabled bool
	}{
		{path: "invalid_port_based.yaml", enabled: false},
		{path: "receiver/noprotocols.yaml", enabled: true},
		{path: "receiver/simple.yaml", enabled: true},
		{path: "receiver/null.yaml", enabled: true},
		{path: "receiver/advanced.yaml", enabled: true},
	}

	for _, testInstance := range tests {
		t.Run(testInstance.path, func(t *testing.T) {
			cfg, err := testutil.LoadConfig("./testdata/" + testInstance.path)
			require.NoError(t, err)
			assert.Equal(t, testInstance.enabled, IsEnabled(cfg))
		})
	}
}

func TestIsEnabledEnv(t *testing.T) {
	t.Setenv("DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT", "0.0.0.0:9993")
	cfg, err := testutil.LoadConfig("./testdata/empty.yaml")
	require.NoError(t, err)
	assert.True(t, IsEnabled(cfg))
}

func TestFromAgentConfigReceiver(t *testing.T) {
	tests := []struct {
		path string
		cfg  PipelineConfig
		err  string
	}{
		{
			path: "receiver/noprotocols.yaml",
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{},
				TracePort:          5003,
				MetricsEnabled:     true,
				TracesEnabled:      true,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
		{
			path: "receiver/simple.yaml",
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": nil,
						"http": nil,
					},
				},
				TracePort:      5003,
				MetricsEnabled: true,
				TracesEnabled:  true,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
		{
			path: "receiver/null.yaml",
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": nil,
						"http": nil,
					},
				},
				TracePort:      5003,
				MetricsEnabled: true,
				TracesEnabled:  true,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
		{
			path: "receiver/advanced.yaml",
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": map[string]interface{}{
							"endpoint":               "0.0.0.0:5678",
							"max_concurrent_streams": 16,
							"transport":              "tcp",
							"keepalive": map[string]interface{}{
								"enforcement_policy": map[string]interface{}{
									"min_time": "10m",
								},
							},
						},
						"http": map[string]interface{}{
							"endpoint": "localhost:1234",
							"cors": map[string]interface{}{
								"allowed_origins": []interface{}{"http://test.com"},
								"allowed_headers": []interface{}{"ExampleHeader"},
							},
						},
					},
				},
				TracePort:      5003,
				MetricsEnabled: true,
				TracesEnabled:  true,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
	}

	for _, testInstance := range tests {
		t.Run(testInstance.path, func(t *testing.T) {
			cfg, err := testutil.LoadConfig("./testdata/" + testInstance.path)
			require.NoError(t, err)
			pcfg, err := FromAgentConfig(cfg)
			if err != nil || testInstance.err != "" {
				assert.Equal(t, testInstance.err, err.Error())
			} else {
				assert.Equal(t, testInstance.cfg, pcfg)
			}
		})
	}
}

func TestFromEnvironmentVariables(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		cfg  PipelineConfig
		err  string
	}{
		{
			name: "only gRPC",
			env: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT": "0.0.0.0:9999",
			},
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": map[string]interface{}{
							"endpoint": "0.0.0.0:9999",
						},
					},
				},
				MetricsEnabled: true,
				TracesEnabled:  true,
				TracePort:      5003,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
		{
			name: "HTTP + gRPC",
			env: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT": "0.0.0.0:9997",
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT": "0.0.0.0:9998",
			},
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": map[string]interface{}{
							"endpoint": "0.0.0.0:9997",
						},
						"http": map[string]interface{}{
							"endpoint": "0.0.0.0:9998",
						},
					},
				},
				MetricsEnabled: true,
				TracesEnabled:  true,
				TracePort:      5003,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
				},
			},
		},
		{
			name: "HTTP + gRPC, metrics config",
			env: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT": "0.0.0.0:9995",
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT": "0.0.0.0:9996",
				"DD_OTLP_CONFIG_METRICS_DELTA_TTL":                "2400",
				"DD_OTLP_CONFIG_METRICS_HISTOGRAMS_MODE":          "counters",
			},
			cfg: PipelineConfig{
				OTLPReceiverConfig: map[string]interface{}{
					"protocols": map[string]interface{}{
						"grpc": map[string]interface{}{
							"endpoint": "0.0.0.0:9995",
						},
						"http": map[string]interface{}{
							"endpoint": "0.0.0.0:9996",
						},
					},
				},
				MetricsEnabled: true,
				TracesEnabled:  true,
				TracePort:      5003,
				Metrics: map[string]interface{}{
					"enabled":         true,
					"tag_cardinality": "low",
					"delta_ttl":       "2400",
					"histograms": map[string]interface{}{
						"mode": "counters",
					},
				},
			},
		},
	}
	for _, testInstance := range tests {
		t.Run(testInstance.name, func(t *testing.T) {
			for env, val := range testInstance.env {
				t.Setenv(env, val)
			}
			cfg, err := testutil.LoadConfig("./testdata/empty.yaml")
			require.NoError(t, err)
			pcfg, err := FromAgentConfig(cfg)
			if err != nil || testInstance.err != "" {
				assert.Equal(t, testInstance.err, err.Error())
			} else {
				assert.Equal(t, testInstance.cfg, pcfg)
			}
		})
	}
}

func TestFromAgentConfigMetrics(t *testing.T) {
	tests := []struct {
		path string
		cfg  PipelineConfig
		err  string
	}{
		{
			path: "metrics/allconfig.yaml",
			cfg: PipelineConfig{
				OTLPReceiverConfig: testutil.OTLPConfigFromPorts("localhost", 5678, 1234),
				TracePort:          5003,
				MetricsEnabled:     true,
				TracesEnabled:      true,
				Metrics: map[string]interface{}{
					"enabled":                     true,
					"delta_ttl":                   2400,
					"resource_attributes_as_tags": true,
					"instrumentation_library_metadata_as_tags": true,
					"tag_cardinality":                          "orchestrator",
					"histograms": map[string]interface{}{
						"mode":                   "counters",
						"send_count_sum_metrics": true,
					},
				},
			},
		},
	}

	for _, testInstance := range tests {
		t.Run(testInstance.path, func(t *testing.T) {
			cfg, err := testutil.LoadConfig("./testdata/" + testInstance.path)
			require.NoError(t, err)
			pcfg, err := FromAgentConfig(cfg)
			if err != nil || testInstance.err != "" {
				assert.Equal(t, testInstance.err, err.Error())
			} else {
				assert.Equal(t, testInstance.cfg, pcfg)
			}
		})
	}
}

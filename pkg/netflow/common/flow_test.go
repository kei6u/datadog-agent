package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFlow_AggregationHash(t *testing.T) {
	allHash := make(map[uint64]bool)
	origFlow := Flow{
		Namespace:      "default",
		ExporterAddr:   []byte{127, 0, 0, 1},
		SrcAddr:        []byte{1, 2, 3, 4},
		DstAddr:        []byte{2, 3, 4, 5},
		IPProtocol:     6,
		SrcPort:        2000,
		DstPort:        80,
		InputInterface: 1,
		Tos:            0,
	}
	origHash := origFlow.AggregationHash()
	assert.Equal(t, uint64(0x5f66aff870a0f86a), origHash)
	allHash[origHash] = true

	flow := origFlow
	flow.Namespace = "my-new-ns"
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.ExporterAddr = []byte{127, 0, 0, 2}
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.SrcAddr = []byte{1, 2, 3, 5}
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.DstAddr = []byte{2, 3, 4, 6}
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.IPProtocol = 7
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.SrcPort = 3000
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.DstPort = 443
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.InputInterface = 2
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	flow = origFlow
	flow.Tos = 1
	assert.NotEqual(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	// OutputInterface is not a key field, changing it should not change the hash
	flow = origFlow
	flow.OutputInterface = 1
	assert.Equal(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	// EtherType is not a key field, changing it should not change the hash
	flow = origFlow
	flow.EtherType = 1
	assert.Equal(t, origHash, flow.AggregationHash())
	allHash[flow.AggregationHash()] = true

	// Should contain expected number of different hashes
	assert.Equal(t, 10, len(allHash))
}

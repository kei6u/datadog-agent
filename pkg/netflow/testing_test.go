package netflow

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/netflow/goflowlib"
	"github.com/DataDog/datadog-agent/pkg/netflow/payload"
	"github.com/netsampler/goflow2/utils"
	"github.com/sirupsen/logrus"
	"net"
)

// NetFlow5 example data from goflow repo:
// https://github.com/netsampler/goflow2/blob/5300494e478567a0fb9b8de0c504d9442260d0ad/decoders/netflowlegacy/netflow_test.go#L11-L32
var mockNetflowV5Data = []byte{
	0x00, 0x05, 0x00, 0x06, 0x00, 0x82, 0xc3, 0x48, 0x5b, 0xcd, 0xba, 0x1b, 0x05, 0x97, 0x6d, 0xc7,
	0x00, 0x00, 0x64, 0x3d, 0x08, 0x08, 0x00, 0x00, 0x0a, 0x80, 0x02, 0x79, 0x0a, 0x80, 0x02, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x4e,
	0x00, 0x82, 0x9b, 0x8c, 0x00, 0x82, 0x9b, 0x90, 0x1f, 0x90, 0xb9, 0x18, 0x00, 0x1b, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02, 0x77, 0x0a, 0x81, 0x02, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x94,
	0x00, 0x82, 0x95, 0xa9, 0x00, 0x82, 0x9a, 0xfb, 0x1f, 0x90, 0xc1, 0x2c, 0x00, 0x12, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x81, 0x02, 0x01, 0x0a, 0x80, 0x02, 0x77,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xc2,
	0x00, 0x82, 0x95, 0xa9, 0x00, 0x82, 0x9a, 0xfc, 0xc1, 0x2c, 0x1f, 0x90, 0x00, 0x16, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02, 0x01, 0x0a, 0x80, 0x02, 0x79,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0xf1,
	0x00, 0x82, 0x9b, 0x8c, 0x00, 0x82, 0x9b, 0x8f, 0xb9, 0x18, 0x1f, 0x90, 0x00, 0x1b, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02, 0x01, 0x0a, 0x80, 0x02, 0x79,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x2e,
	0x00, 0x82, 0x9b, 0x90, 0x00, 0x82, 0x9b, 0x9d, 0xb9, 0x1a, 0x1f, 0x90, 0x00, 0x1b, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02, 0x79, 0x0a, 0x80, 0x02, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x0b, 0xac,
	0x00, 0x82, 0x9b, 0x90, 0x00, 0x82, 0x9b, 0x9d, 0x1f, 0x90, 0xb9, 0x1a, 0x00, 0x1b, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

type dummyFlowProcessor struct {
	receivedMessages chan interface{}
	stopped          bool
}

func (d *dummyFlowProcessor) FlowRoutine(workers int, addr string, port int, reuseport bool) error {
	return utils.UDPStoppableRoutine(make(chan struct{}), "test_udp", func(msg interface{}) error {
		d.receivedMessages <- msg
		return nil
	}, 3, addr, port, false, logrus.StandardLogger())
}

func (d *dummyFlowProcessor) Shutdown() {
	d.stopped = true
}

func sendUDPPacket(port uint16, data []byte) error {
	udpConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	_, err = udpConn.Write(data)
	udpConn.Close()
	return err
}

func replaceWithDummyFlowProcessor(server *Server, port uint16) *dummyFlowProcessor {
	// Testing using a dummyFlowProcessor since we can't test using real goflow flow processor
	// due to this race condition https://github.com/netsampler/goflow2/issues/83
	flowProcessor := &dummyFlowProcessor{}
	listener := server.listeners[0]
	listener.flowState = &goflowlib.FlowStateWrapper{
		State:    flowProcessor,
		Hostname: "abc",
		Port:     port,
	}
	return flowProcessor
}

func findEventBySourceDest(events []*message.Message, sourceIP string, destIP string) (payload.FlowPayload, error) {
	for _, event := range events {
		actualFlow := payload.FlowPayload{}
		_ = json.Unmarshal(event.Content, &actualFlow)
		if actualFlow.Source.IP == sourceIP && actualFlow.Destination.IP == destIP {
			return actualFlow, nil
		}
	}
	return payload.FlowPayload{}, fmt.Errorf("no event found that matches `source=%s`, `destination=%s", sourceIP, destIP)
}

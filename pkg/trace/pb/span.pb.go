// Code generated by protoc-gen-gogo.
// source: span.proto
// DO NOT EDIT!

/*
	Package pb is a generated protocol buffer package.

	It is generated from these files:
		span.proto

	It has these top-level messages:
		Span
*/
package pb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type Span struct {
	Service  string             `protobuf:"bytes,1,opt,name=service,proto3" json:"service" msg:"service"`
	Name     string             `protobuf:"bytes,2,opt,name=name,proto3" json:"name" msg:"name"`
	Resource string             `protobuf:"bytes,3,opt,name=resource,proto3" json:"resource" msg:"resource"`
	TraceID  uint64             `protobuf:"varint,4,opt,name=traceID,proto3" json:"trace_id" msg:"trace_id"`
	SpanID   uint64             `protobuf:"varint,5,opt,name=spanID,proto3" json:"span_id" msg:"span_id"`
	ParentID uint64             `protobuf:"varint,6,opt,name=parentID,proto3" json:"parent_id" msg:"parent_id"`
	Start    int64              `protobuf:"varint,7,opt,name=start,proto3" json:"start" msg:"start"`
	Duration int64              `protobuf:"varint,8,opt,name=duration,proto3" json:"duration" msg:"duration"`
	Error    int32              `protobuf:"varint,9,opt,name=error,proto3" json:"error" msg:"error"`
	Meta     map[string]string  `protobuf:"bytes,10,rep,name=meta" json:"meta" msg:"meta" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Metrics  map[string]float64 `protobuf:"bytes,11,rep,name=metrics" json:"metrics" msg:"metrics" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"fixed64,2,opt,name=value,proto3"`
	Type     string             `protobuf:"bytes,12,opt,name=type,proto3" json:"type" msg:"type"`
}

func (m *Span) Reset()                    { *m = Span{} }
func (m *Span) String() string            { return proto.CompactTextString(m) }
func (*Span) ProtoMessage()               {}
func (*Span) Descriptor() ([]byte, []int) { return fileDescriptorSpan, []int{0} }

func (m *Span) GetMeta() map[string]string {
	if m != nil {
		return m.Meta
	}
	return nil
}

func (m *Span) GetMetrics() map[string]float64 {
	if m != nil {
		return m.Metrics
	}
	return nil
}

func init() {
	proto.RegisterType((*Span)(nil), "pb.Span")
}
func (m *Span) Marshal() (data []byte, err error) {
	size := m.Size()
	data = make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *Span) MarshalTo(data []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Service) > 0 {
		data[i] = 0xa
		i++
		i = encodeVarintSpan(data, i, uint64(len(m.Service)))
		i += copy(data[i:], m.Service)
	}
	if len(m.Name) > 0 {
		data[i] = 0x12
		i++
		i = encodeVarintSpan(data, i, uint64(len(m.Name)))
		i += copy(data[i:], m.Name)
	}
	if len(m.Resource) > 0 {
		data[i] = 0x1a
		i++
		i = encodeVarintSpan(data, i, uint64(len(m.Resource)))
		i += copy(data[i:], m.Resource)
	}
	if m.TraceID != 0 {
		data[i] = 0x20
		i++
		i = encodeVarintSpan(data, i, uint64(m.TraceID))
	}
	if m.SpanID != 0 {
		data[i] = 0x28
		i++
		i = encodeVarintSpan(data, i, uint64(m.SpanID))
	}
	if m.ParentID != 0 {
		data[i] = 0x30
		i++
		i = encodeVarintSpan(data, i, uint64(m.ParentID))
	}
	if m.Start != 0 {
		data[i] = 0x38
		i++
		i = encodeVarintSpan(data, i, uint64(m.Start))
	}
	if m.Duration != 0 {
		data[i] = 0x40
		i++
		i = encodeVarintSpan(data, i, uint64(m.Duration))
	}
	if m.Error != 0 {
		data[i] = 0x48
		i++
		i = encodeVarintSpan(data, i, uint64(m.Error))
	}
	if len(m.Meta) > 0 {
		for k, _ := range m.Meta {
			data[i] = 0x52
			i++
			v := m.Meta[k]
			mapSize := 1 + len(k) + sovSpan(uint64(len(k))) + 1 + len(v) + sovSpan(uint64(len(v)))
			i = encodeVarintSpan(data, i, uint64(mapSize))
			data[i] = 0xa
			i++
			i = encodeVarintSpan(data, i, uint64(len(k)))
			i += copy(data[i:], k)
			data[i] = 0x12
			i++
			i = encodeVarintSpan(data, i, uint64(len(v)))
			i += copy(data[i:], v)
		}
	}
	if len(m.Metrics) > 0 {
		for k, _ := range m.Metrics {
			data[i] = 0x5a
			i++
			v := m.Metrics[k]
			mapSize := 1 + len(k) + sovSpan(uint64(len(k))) + 1 + 8
			i = encodeVarintSpan(data, i, uint64(mapSize))
			data[i] = 0xa
			i++
			i = encodeVarintSpan(data, i, uint64(len(k)))
			i += copy(data[i:], k)
			data[i] = 0x11
			i++
			i = encodeFixed64Span(data, i, uint64(math.Float64bits(float64(v))))
		}
	}
	if len(m.Type) > 0 {
		data[i] = 0x62
		i++
		i = encodeVarintSpan(data, i, uint64(len(m.Type)))
		i += copy(data[i:], m.Type)
	}
	return i, nil
}

func encodeFixed64Span(data []byte, offset int, v uint64) int {
	data[offset] = uint8(v)
	data[offset+1] = uint8(v >> 8)
	data[offset+2] = uint8(v >> 16)
	data[offset+3] = uint8(v >> 24)
	data[offset+4] = uint8(v >> 32)
	data[offset+5] = uint8(v >> 40)
	data[offset+6] = uint8(v >> 48)
	data[offset+7] = uint8(v >> 56)
	return offset + 8
}
func encodeFixed32Span(data []byte, offset int, v uint32) int {
	data[offset] = uint8(v)
	data[offset+1] = uint8(v >> 8)
	data[offset+2] = uint8(v >> 16)
	data[offset+3] = uint8(v >> 24)
	return offset + 4
}
func encodeVarintSpan(data []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		data[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	data[offset] = uint8(v)
	return offset + 1
}
func (m *Span) Size() (n int) {
	var l int
	_ = l
	l = len(m.Service)
	if l > 0 {
		n += 1 + l + sovSpan(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovSpan(uint64(l))
	}
	l = len(m.Resource)
	if l > 0 {
		n += 1 + l + sovSpan(uint64(l))
	}
	if m.TraceID != 0 {
		n += 1 + sovSpan(uint64(m.TraceID))
	}
	if m.SpanID != 0 {
		n += 1 + sovSpan(uint64(m.SpanID))
	}
	if m.ParentID != 0 {
		n += 1 + sovSpan(uint64(m.ParentID))
	}
	if m.Start != 0 {
		n += 1 + sovSpan(uint64(m.Start))
	}
	if m.Duration != 0 {
		n += 1 + sovSpan(uint64(m.Duration))
	}
	if m.Error != 0 {
		n += 1 + sovSpan(uint64(m.Error))
	}
	if len(m.Meta) > 0 {
		for k, v := range m.Meta {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovSpan(uint64(len(k))) + 1 + len(v) + sovSpan(uint64(len(v)))
			n += mapEntrySize + 1 + sovSpan(uint64(mapEntrySize))
		}
	}
	if len(m.Metrics) > 0 {
		for k, v := range m.Metrics {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovSpan(uint64(len(k))) + 1 + 8
			n += mapEntrySize + 1 + sovSpan(uint64(mapEntrySize))
		}
	}
	l = len(m.Type)
	if l > 0 {
		n += 1 + l + sovSpan(uint64(l))
	}
	return n
}

func sovSpan(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozSpan(x uint64) (n int) {
	return sovSpan(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Span) Unmarshal(data []byte) error {
	l := len(data)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowSpan
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := data[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Span: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Span: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Service", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Service = string(data[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(data[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Resource", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Resource = string(data[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TraceID", wireType)
			}
			m.TraceID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.TraceID |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field SpanID", wireType)
			}
			m.SpanID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.SpanID |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ParentID", wireType)
			}
			m.ParentID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.ParentID |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Start", wireType)
			}
			m.Start = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.Start |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Duration", wireType)
			}
			m.Duration = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.Duration |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 9:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Error", wireType)
			}
			m.Error = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				m.Error |= (int32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 10:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Meta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var keykey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				keykey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			var stringLenmapkey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLenmapkey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLenmapkey := int(stringLenmapkey)
			if intStringLenmapkey < 0 {
				return ErrInvalidLengthSpan
			}
			postStringIndexmapkey := iNdEx + intStringLenmapkey
			if postStringIndexmapkey > l {
				return io.ErrUnexpectedEOF
			}
			mapkey := string(data[iNdEx:postStringIndexmapkey])
			iNdEx = postStringIndexmapkey
			if m.Meta == nil {
				m.Meta = make(map[string]string)
			}
			if iNdEx < postIndex {
				var valuekey uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowSpan
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := data[iNdEx]
					iNdEx++
					valuekey |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				var stringLenmapvalue uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowSpan
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := data[iNdEx]
					iNdEx++
					stringLenmapvalue |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				intStringLenmapvalue := int(stringLenmapvalue)
				if intStringLenmapvalue < 0 {
					return ErrInvalidLengthSpan
				}
				postStringIndexmapvalue := iNdEx + intStringLenmapvalue
				if postStringIndexmapvalue > l {
					return io.ErrUnexpectedEOF
				}
				mapvalue := string(data[iNdEx:postStringIndexmapvalue])
				iNdEx = postStringIndexmapvalue
				m.Meta[mapkey] = mapvalue
			} else {
				var mapvalue string
				m.Meta[mapkey] = mapvalue
			}
			iNdEx = postIndex
		case 11:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var keykey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				keykey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			var stringLenmapkey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLenmapkey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLenmapkey := int(stringLenmapkey)
			if intStringLenmapkey < 0 {
				return ErrInvalidLengthSpan
			}
			postStringIndexmapkey := iNdEx + intStringLenmapkey
			if postStringIndexmapkey > l {
				return io.ErrUnexpectedEOF
			}
			mapkey := string(data[iNdEx:postStringIndexmapkey])
			iNdEx = postStringIndexmapkey
			if m.Metrics == nil {
				m.Metrics = make(map[string]float64)
			}
			if iNdEx < postIndex {
				var valuekey uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowSpan
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := data[iNdEx]
					iNdEx++
					valuekey |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				var mapvaluetemp uint64
				if (iNdEx + 8) > l {
					return io.ErrUnexpectedEOF
				}
				iNdEx += 8
				mapvaluetemp = uint64(data[iNdEx-8])
				mapvaluetemp |= uint64(data[iNdEx-7]) << 8
				mapvaluetemp |= uint64(data[iNdEx-6]) << 16
				mapvaluetemp |= uint64(data[iNdEx-5]) << 24
				mapvaluetemp |= uint64(data[iNdEx-4]) << 32
				mapvaluetemp |= uint64(data[iNdEx-3]) << 40
				mapvaluetemp |= uint64(data[iNdEx-2]) << 48
				mapvaluetemp |= uint64(data[iNdEx-1]) << 56
				mapvalue := math.Float64frombits(mapvaluetemp)
				m.Metrics[mapkey] = mapvalue
			} else {
				var mapvalue float64
				m.Metrics[mapkey] = mapvalue
			}
			iNdEx = postIndex
		case 12:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSpan
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Type = string(data[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipSpan(data[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthSpan
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipSpan(data []byte) (n int, err error) {
	l := len(data)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowSpan
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := data[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if data[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowSpan
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := data[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthSpan
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowSpan
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := data[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipSpan(data[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthSpan = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowSpan   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("span.proto", fileDescriptorSpan) }

var fileDescriptorSpan = []byte{
	// 488 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x93, 0xcd, 0x8e, 0xd3, 0x30,
	0x10, 0xc7, 0x71, 0x9b, 0x7e, 0xb9, 0x0b, 0xac, 0x2c, 0x40, 0x56, 0x85, 0x92, 0xc8, 0xa7, 0x08,
	0x89, 0xac, 0x04, 0x08, 0x56, 0x15, 0xe2, 0x50, 0x95, 0x43, 0x0f, 0x7b, 0x31, 0x0f, 0x80, 0x9c,
	0xac, 0x29, 0x11, 0xe4, 0x43, 0x8e, 0xb3, 0x52, 0xdf, 0x82, 0x47, 0xe0, 0x71, 0x38, 0xf2, 0x04,
	0x11, 0x2a, 0xb7, 0x1c, 0xfb, 0x04, 0xc8, 0xe3, 0xc4, 0xf4, 0xb6, 0xb7, 0xfc, 0x7f, 0x33, 0x7f,
	0x8f, 0x67, 0x3c, 0xc1, 0xb8, 0xae, 0x44, 0x11, 0x57, 0xaa, 0xd4, 0x25, 0x19, 0x55, 0xc9, 0xea,
	0xe5, 0x3e, 0xd3, 0x5f, 0x9b, 0x24, 0x4e, 0xcb, 0xfc, 0x6a, 0x5f, 0xee, 0xcb, 0x2b, 0x08, 0x25,
	0xcd, 0x17, 0x50, 0x20, 0xe0, 0xcb, 0x5a, 0xd8, 0xcf, 0x29, 0xf6, 0x3e, 0x55, 0xa2, 0x20, 0x6f,
	0xf1, 0xac, 0x96, 0xea, 0x2e, 0x4b, 0x25, 0x45, 0x21, 0x8a, 0x16, 0x9b, 0xe7, 0x5d, 0x1b, 0x0c,
	0xe8, 0xd4, 0x06, 0x0f, 0xf3, 0x7a, 0xbf, 0x66, 0xbd, 0x66, 0x7c, 0x88, 0x90, 0x17, 0xd8, 0x2b,
	0x44, 0x2e, 0xe9, 0x08, 0x4c, 0xcf, 0xba, 0x36, 0x00, 0x7d, 0x6a, 0x03, 0x0c, 0x0e, 0x23, 0x18,
	0x07, 0x46, 0xd6, 0x78, 0xae, 0x64, 0x5d, 0x36, 0x2a, 0x95, 0x74, 0x0c, 0xf9, 0x7e, 0xd7, 0x06,
	0x8e, 0x9d, 0xda, 0xe0, 0x11, 0x78, 0x06, 0xc0, 0xb8, 0x8b, 0x91, 0x6b, 0x3c, 0xd3, 0x4a, 0xa4,
	0x72, 0xb7, 0xa5, 0x5e, 0x88, 0x22, 0xcf, 0x5a, 0x01, 0x7d, 0xce, 0x6e, 0x9d, 0x75, 0x00, 0x8c,
	0x0f, 0xe9, 0xe4, 0x0d, 0x9e, 0x9a, 0x19, 0xed, 0xb6, 0x74, 0x02, 0x46, 0xdb, 0x58, 0x25, 0x0a,
	0xeb, 0xeb, 0x1b, 0xb3, 0x9a, 0xf1, 0x3e, 0x97, 0xbc, 0xc7, 0xf3, 0x4a, 0x28, 0x59, 0xe8, 0xdd,
	0x96, 0x4e, 0xc1, 0x17, 0x76, 0x6d, 0xb0, 0xb0, 0xcc, 0x3a, 0x1f, 0x83, 0xd3, 0x11, 0xc6, 0x9d,
	0x83, 0xc4, 0x78, 0x52, 0x6b, 0xa1, 0x34, 0x9d, 0x85, 0x28, 0x1a, 0x6f, 0x68, 0xd7, 0x06, 0x16,
	0x9c, 0xda, 0x60, 0x69, 0x0b, 0x1a, 0xc5, 0xb8, 0xa5, 0x66, 0x32, 0xb7, 0x8d, 0x12, 0x3a, 0x2b,
	0x0b, 0x3a, 0x07, 0x0b, 0xb4, 0x37, 0x30, 0xd7, 0xde, 0x00, 0x18, 0x77, 0x31, 0x53, 0x4b, 0x2a,
	0x55, 0x2a, 0xba, 0x08, 0x51, 0x34, 0xb1, 0xb5, 0x00, 0xb8, 0x5a, 0xa0, 0x18, 0xb7, 0x94, 0x7c,
	0xc0, 0x5e, 0x2e, 0xb5, 0xa0, 0x38, 0x1c, 0x47, 0xcb, 0x57, 0x24, 0xae, 0x92, 0xd8, 0x6c, 0x40,
	0x7c, 0x23, 0xb5, 0xf8, 0x58, 0x68, 0x75, 0xb0, 0xaf, 0x68, 0x72, 0xdc, 0x2b, 0x1a, 0xc1, 0x38,
	0x30, 0x72, 0x83, 0x67, 0xb9, 0xd4, 0x2a, 0x4b, 0x6b, 0xba, 0x84, 0x23, 0x9e, 0x9e, 0x1f, 0x61,
	0xb8, 0x3d, 0x05, 0xe6, 0xdc, 0x67, 0xba, 0x39, 0xf7, 0x9a, 0xf1, 0x21, 0x62, 0x16, 0x48, 0x1f,
	0x2a, 0x49, 0x2f, 0xfe, 0x2f, 0x90, 0xd1, 0xae, 0xb4, 0x11, 0x8c, 0x03, 0x5b, 0xbd, 0xc3, 0x0b,
	0x77, 0x4b, 0x72, 0x89, 0xc7, 0xdf, 0xe4, 0xc1, 0x6e, 0x2b, 0x37, 0x9f, 0xe4, 0x09, 0x9e, 0xdc,
	0x89, 0xef, 0x4d, 0xbf, 0x8c, 0xdc, 0x8a, 0xf5, 0xe8, 0x1a, 0xad, 0xd6, 0xf8, 0xe2, 0xfc, 0x6e,
	0xf7, 0x79, 0xd1, 0x99, 0x77, 0x73, 0xf9, 0xeb, 0xe8, 0xa3, 0xdf, 0x47, 0x1f, 0xfd, 0x39, 0xfa,
	0xe8, 0xc7, 0x5f, 0xff, 0x41, 0x32, 0x85, 0x7f, 0xe7, 0xf5, 0xbf, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xeb, 0x8e, 0xfc, 0x70, 0x7c, 0x03, 0x00, 0x00,
}

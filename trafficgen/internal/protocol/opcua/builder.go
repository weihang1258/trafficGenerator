package opcua

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/trafficgen/trafficgen/internal/core"
)

// OPC UA TCP wire framing (OPC UA Part 6 §7.1.2): 4-byte message type +
// 4-byte little-endian MessageSize (including the 8-byte header) + body.
func uaFrame(kind string, body []byte) ([]byte, error) {
	if len(kind) != 4 {
		return nil, fmt.Errorf("opcua: invalid message kind")
	}
	if len(body)+8 > 0xffff {
		return nil, fmt.Errorf("opcua: MessageSize %d exceeds UInt16", len(body)+8)
	}
	out := make([]byte, 8+len(body))
	copy(out, kind)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	copy(out[8:], body)
	return out, nil
}

func u32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

// BuildHEL encodes the client Hello (§7.1.2.2): protocol version, buffer
// sizes, max message size / chunk count, endpoint URL string.
func BuildHEL(endpointURL string) ([]byte, error) {
	body := make([]byte, 24+len(endpointURL))
	u32(body[0:4], 0)      // protocolVersion
	u32(body[4:8], 65536)  // receiveBufferSize
	u32(body[8:12], 65536) // sendBufferSize
	u32(body[12:16], 0)    // maxMessageSize
	u32(body[16:20], 0)    // maxChunkCount
	u32(body[20:24], uint32(len(endpointURL)))
	copy(body[24:], endpointURL)
	return uaFrame("HELF", body)
}

// BuildACK encodes the server Acknowledge (§7.1.2.3), fixed 20-byte body.
func BuildACK() ([]byte, error) {
	body := make([]byte, 20)
	u32(body[0:4], 0)      // protocolVersion
	u32(body[4:8], 65536)  // receiveBufferSize
	u32(body[8:12], 65536) // sendBufferSize
	u32(body[12:16], 0)    // maxMessageSize
	u32(body[16:20], 0)    // maxChunkCount
	return uaFrame("ACKF", body)
}

// serviceNodeID writes a four-byte-encoded TypeId node id (0x01, NS 0,
// numeric identifier little-endian).
func serviceNodeID(b []byte, id uint16) {
	b[0] = 0x01
	b[1] = 0x00
	binary.LittleEndian.PutUint16(b[2:4], id)
}

// parseFourByteNodeID parses "ns=<u8>;i=<u16>" into the four-byte NodeId
// wire form (encoding mask 0x01, namespace byte, little-endian identifier).
func parseFourByteNodeID(s string) ([4]byte, error) {
	var ns, id int
	if n, err := fmt.Sscanf(s, "ns=%d;i=%d", &ns, &id); err != nil || n != 2 {
		return [4]byte{}, fmt.Errorf("opcua: node id %q is not ns=<int>;i=<int>", s)
	}
	if ns < 0 || ns > 255 || id < 0 || id > 65535 {
		return [4]byte{}, fmt.Errorf("opcua: node id %q exceeds four-byte encoding", s)
	}
	var b [4]byte
	b[0] = 0x01
	b[1] = byte(ns)
	binary.LittleEndian.PutUint16(b[2:4], uint16(id))
	return b, nil
}

// putRequestHeader appends the OPC UA RequestHeader (Part 4 §7.29):
// AuthenticationToken node id(4) + timestamp(8) + requestHandle(4) +
// returnDiagnostics(4) + auditEntryId null string(4) + timeoutHint(4) +
// additionalHeader null extension object(3) = 31 bytes.
func putRequestHeader(dst []byte, handle uint32) {
	serviceNodeID(dst[0:4], 0)
	binary.LittleEndian.PutUint64(dst[4:12], 0)
	binary.LittleEndian.PutUint32(dst[12:16], handle)
	binary.LittleEndian.PutUint32(dst[16:20], 0)
	binary.LittleEndian.PutUint32(dst[20:24], 0)
	binary.LittleEndian.PutUint32(dst[24:28], 60000)
	dst[28] = 0x00 // additionalHeader: two-byte numeric id 0
	dst[29] = 0x00 // namespace (part of the null TypeId)
	dst[30] = 0x00 // encoding mask: no body
}

// putResponseHeader writes the 24-byte ResponseHeader (Part 4 §7.30):
// timestamp(8) + requestHandle(4) + serviceResult(4) + serviceDiagnostics
// null DiagnosticInfo(1) + stringTable null array(4) + additionalHeader null
// ExtensionObject(3). tshark 3.6.14 parses exactly this layout — ServiceResult
// is a u32 between requestHandle and the diagnostics mask (decoding a header
// written without it surfaced the mask byte as ServiceResult 0xffffff00 and
// shifted every later field).
func putResponseHeader(dst []byte, handle, serviceResult uint32) {
	binary.LittleEndian.PutUint64(dst[0:8], 0)
	binary.LittleEndian.PutUint32(dst[8:12], handle)
	binary.LittleEndian.PutUint32(dst[12:16], serviceResult)
	dst[16] = 0x00 // serviceDiagnostics: null DiagnosticInfo mask
	binary.LittleEndian.PutUint32(dst[17:21], 0xFFFFFFFF)
	dst[21], dst[22], dst[23] = 0x00, 0x00, 0x00
}

func putU32(dst []byte, v uint32) {
	binary.LittleEndian.PutUint32(dst, v)
}

// BuildOPN encodes OpenSecureChannel (§7.1.2.4). channelID is 0 for the
// request and the server-assigned id (1) for the response.
func BuildOPN(channelID uint32, mode string) ([]byte, error) {
	// channel(4) + 3 empty security strings(12) + seq(4) + reqId(4)
	// + TypeId(4) + RequestHeader(31) + protocolVersion(4) + requestType(4)
	// + securityMode(4) + clientNonce(4) + requestedLifetime(4) = 79
	body := make([]byte, 79)
	putU32(body[0:4], channelID)
	// securityPolicyUri/senderCertificate/receiverCertificateThumbprint:
	// null strings (length 0 each).
	putU32(body[16:20], 1) // sequenceNumber
	putU32(body[20:24], 1) // requestId
	serviceNodeID(body[24:28], 446)
	putRequestHeader(body[28:59], 1)
	putU32(body[59:63], 0) // clientProtocolVersion
	putU32(body[63:67], 0) // requestType: ISSUE
	securityMode := uint32(0x01)
	if mode == "sign" {
		securityMode = 0x02
	}
	putU32(body[67:71], securityMode)
	putU32(body[71:75], 0)       // clientNonce: null bytestring
	putU32(body[75:79], 3600000) // requestedLifetime
	return uaFrame("OPNF", body)
}

// msgHeader writes the MSG/CLO symmetric header: secure channel id, token
// id, sequence number, request id.
func msgHeader(body []byte, channelID, tokenID, seq, reqID uint32) {
	u32(body[0:4], channelID)
	u32(body[4:8], tokenID)
	u32(body[8:12], seq)
	u32(body[12:16], reqID)
}

// BuildMSG encodes a symmetric service message: header + TypeId + the full
// service structure (no extra encoding byte — the service body directly
// follows the TypeId, which is what the tshark dissector walks).
func BuildMSG(channelID, tokenID, seq, reqID uint32, serviceID uint16, service []byte) ([]byte, error) {
	body := make([]byte, 16+4+len(service))
	msgHeader(body, channelID, tokenID, seq, reqID)
	serviceNodeID(body[16:20], serviceID)
	copy(body[20:], service)
	return uaFrame("MSGF", body)
}

// BuildCLO encodes CloseSecureChannel: symmetric header + TypeId 452 +
// CloseSecureChannelRequest (a bare RequestHeader).
func BuildCLO(channelID, tokenID, seq, reqID uint32) ([]byte, error) {
	body := make([]byte, 16+4+31)
	msgHeader(body, channelID, tokenID, seq, reqID)
	serviceNodeID(body[16:20], 452)
	putRequestHeader(body[20:51], 0)
	return uaFrame("CLOF", body)
}

// --- service structures -------------------------------------------------

// nullQualifiedName writes a null QualifiedName (NamespaceIndex 0 + null
// string) — 6 bytes, not 1: tshark decodes a bare 0x00 as a bogus Id.
func putNullQualifiedName(dst []byte) {
	binary.LittleEndian.PutUint16(dst[0:2], 0)
	binary.LittleEndian.PutUint32(dst[2:6], 0xFFFFFFFF)
}

// readRequestBody encodes ReadRequest: RequestHeader(31) + maxAge Double(8)
// + timestampsToReturn(4) + ReadValueIds array. Each ReadValueId is
// NodeId(4) + attributeId(4) + indexRange null string(4) + null
// QualifiedName(6) = 18 bytes. Returns the body and the node count.
func readRequestBody(handle uint32, ops []core.OPCUANodeRead) ([]byte, int, error) {
	n := 0
	for _, op := range ops {
		n += len(op.NodeIDs)
	}
	b := make([]byte, 47+18*n)
	putRequestHeader(b[0:31], handle)
	binary.LittleEndian.PutUint64(b[31:39], 0) // maxAge
	putU32(b[39:43], 0)                        // timestampsToReturn: Source
	putU32(b[43:47], uint32(n))                // ReadValueIds count
	off := 47
	for _, op := range ops {
		for _, nid := range op.NodeIDs {
			nd, err := parseFourByteNodeID(nid)
			if err != nil {
				return nil, 0, err
			}
			copy(b[off:off+4], nd[:])
			off += 4
			putU32(b[off:off+4], op.AttributeID)
			off += 4
			binary.LittleEndian.PutUint32(b[off:off+4], 0xFFFFFFFF) // indexRange null
			off += 4
			putNullQualifiedName(b[off : off+6])
			off += 6
		}
	}
	return b, n, nil
}

// readResponseBody encodes ReadResponse: ResponseHeader(24) + results array
// (per-node statuses stay Good — the injected failure rides the header
// ServiceResult, per the case notes) + null diagnostic array.
func readResponseBody(n int, handle, status uint32) []byte {
	b := make([]byte, 24+4+4*n+4)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], uint32(n))
	putU32(b[28+4*n:32+4*n], 0xFFFFFFFF)
	return b
}

// writeRequestBody encodes WriteRequest: RequestHeader(31) + NodesToWrite
// array. Each WriteValue = NodeId(4) + attributeId(4) + indexRange null(4)
// + DataValue: encoding mask 0x01 (value present) + Variant (encoding byte
// 0x06 Int32 scalar + Int32(4)) = 18 bytes.
func writeRequestBody(handle uint32, op core.OPCUANodeRead) ([]byte, int, error) {
	n := len(op.NodeIDs)
	b := make([]byte, 35+18*n)
	putRequestHeader(b[0:31], handle)
	putU32(b[31:35], uint32(n))
	off := 35
	for _, nid := range op.NodeIDs {
		nd, err := parseFourByteNodeID(nid)
		if err != nil {
			return nil, 0, err
		}
		copy(b[off:off+4], nd[:])
		off += 4
		putU32(b[off:off+4], op.AttributeID)
		off += 4
		binary.LittleEndian.PutUint32(b[off:off+4], 0xFFFFFFFF) // indexRange null
		off += 4
		b[off] = 0x01 // DataValue encoding: value present
		off++
		b[off] = 0x06 // Variant encoding: Int32 scalar
		off++
		putU32(b[off:off+4], 1)
		off += 4
	}
	return b, n, nil
}

// writeResponseBody encodes WriteResponse: ResponseHeader(20) + results
// array (one status per written node) + null diagnostic array.
func writeResponseBody(n int, handle, status uint32) []byte {
	return readResponseBody(n, handle, status)
}

// browseRequestBody encodes BrowseRequest: RequestHeader(31) + View
// (TwoByte NodeId(2) + timestamp(8) + viewVersion(4)) + maxRefs(4) +
// BrowseDescriptions array. Each description = NodeId(4) + direction(4) +
// referenceTypeId TwoByte NodeId(2) + includeSubtypes(1) + nodeClassMask(4)
// + resultMask(4) = 19 bytes.
func browseRequestBody(handle uint32, op core.OPCUANodeRead) ([]byte, int, error) {
	n := len(op.NodeIDs)
	b := make([]byte, 53+19*n)
	putRequestHeader(b[0:31], handle)
	b[31], b[32] = 0x00, 0x00 // View.viewId: TwoByte NodeId 0
	binary.LittleEndian.PutUint64(b[33:41], 0)
	putU32(b[41:45], 0) // viewVersion
	putU32(b[45:49], 0) // requestedMaxReferencesPerNode
	putU32(b[49:53], uint32(n))
	off := 53
	for _, nid := range op.NodeIDs {
		nd, err := parseFourByteNodeID(nid)
		if err != nil {
			return nil, 0, err
		}
		copy(b[off:off+4], nd[:])
		off += 4
		putU32(b[off:off+4], 0) // browseDirection: Forward
		off += 4
		b[off], b[off+1] = 0x00, 33 // referenceTypeId: HierarchicalReferences
		off += 2
		b[off] = 0x01 // includeSubtypes
		off++
		putU32(b[off:off+4], 0) // nodeClassMask
		off += 4
		putU32(b[off:off+4], 63) // resultMask
		off += 4
	}
	return b, n, nil
}

// browseResponseBody encodes BrowseResponse: ResponseHeader(24) + results
// array. Each BrowseResult = status(4) + null continuation point(4) + null
// references(4); then a null diagnostic array.
func browseResponseBody(n int, handle, status uint32) []byte {
	b := make([]byte, 24+4+12*n+4)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], uint32(n))
	off := 28
	for i := 0; i < n; i++ {
		putU32(b[off:off+4], 0)
		putU32(b[off+4:off+8], 0xFFFFFFFF) // continuationPoint null
		putU32(b[off+8:off+12], 0xFFFFFFFF)
		off += 12
	}
	putU32(b[off:off+4], 0xFFFFFFFF)
	return b
}

// createSubRequestBody encodes CreateSubscriptionRequest: RequestHeader(31)
// + requestedPublishingInterval Double(8) + lifetimeCount(4) +
// maxKeepAliveCount(4) + maxNotificationsPerPublish(4) + publishingEnabled(1)
// + priority(1).
func createSubRequestBody(handle uint32, sub *core.OPCUASubConfig) []byte {
	b := make([]byte, 53)
	putRequestHeader(b[0:31], handle)
	binary.LittleEndian.PutUint64(b[31:39], math.Float64bits(float64(sub.PublishingIntervalMs)))
	putU32(b[39:43], 10000) // requestedLifetimeCount
	putU32(b[43:47], sub.MaxKeepAliveCount)
	if sub.MaxKeepAliveCount == 0 {
		putU32(b[43:47], 10)
	}
	putU32(b[47:51], 0) // maxNotificationsPerPublish
	b[51] = 0x01        // publishingEnabled
	b[52] = 0x00        // priority
	return b
}

// createSubResponseBody encodes CreateSubscriptionResponse: ResponseHeader
// (24) + subscriptionId(4) + revisedPublishingInterval Double(8) +
// revisedLifetimeCount(4) + revisedMaxKeepAliveCount(4).
func createSubResponseBody(handle, status uint32, sub *core.OPCUASubConfig) []byte {
	b := make([]byte, 44)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], 1) // subscriptionId
	binary.LittleEndian.PutUint64(b[28:36], math.Float64bits(float64(sub.PublishingIntervalMs)))
	putU32(b[36:40], 10000)
	ka := sub.MaxKeepAliveCount
	if ka == 0 {
		ka = 10
	}
	putU32(b[40:44], ka)
	return b
}

// createMonRequestBody encodes CreateMonitoredItemsRequest: RequestHeader
// (31) + subscriptionId(4) + timestampsToReturn(4) + ItemsToCreate array.
// Each item = ReadValueId(18: NodeId 4 + attrId 4 + null range 4 + null
// QualifiedName 6) + monitoringMode(4) + MonitoringParameters(clientHandle
// 4 + samplingInterval Double 8 + null filter ExtensionObject 3: TwoByte
// NodeId + encoding + queueSize 4 + discardOldest 1 = 20) = 42 bytes.
func createMonRequestBody(handle uint32, sub *core.OPCUASubConfig) ([]byte, int, error) {
	n := len(sub.MonitoredNodes)
	b := make([]byte, 43+42*n)
	putRequestHeader(b[0:31], handle)
	putU32(b[31:35], 1) // subscriptionId
	putU32(b[35:39], 0) // timestampsToReturn
	putU32(b[39:43], uint32(n))
	off := 43
	for i, nid := range sub.MonitoredNodes {
		nd, err := parseFourByteNodeID(nid)
		if err != nil {
			return nil, 0, err
		}
		copy(b[off:off+4], nd[:]) // ItemToMonitor.nodeId
		off += 4
		putU32(b[off:off+4], 13) // attributeId: Value
		off += 4
		binary.LittleEndian.PutUint32(b[off:off+4], 0xFFFFFFFF) // indexRange null
		off += 4
		putNullQualifiedName(b[off : off+6])
		off += 6
		putU32(b[off:off+4], 2) // monitoringMode: Reporting
		off += 4
		putU32(b[off:off+4], uint32(i+1)) // clientHandle
		off += 4
		binary.LittleEndian.PutUint64(b[off:off+8], math.Float64bits(float64(sub.PublishingIntervalMs)))
		off += 8
		b[off], b[off+1] = 0x00, 0x00 // filter TypeId: TwoByte NodeId 0 (mask + identifier)
		off += 2
		b[off] = 0x00 // filter encoding: no body
		off++
		putU32(b[off:off+4], 1) // queueSize
		off += 4
		b[off] = 0x01 // discardOldest
		off++
	}
	return b, n, nil
}

// createMonResponseBody encodes CreateMonitoredItemsResponse: ResponseHeader
// (24) + results array. Each result = status(4) + monitoredItemId NodeId(4)
// + revisedSamplingInterval Double(8) + revisedQueueSize(4) + null
// filterResult(1) = 21 bytes; then a null diagnostic array.
func createMonResponseBody(n int, handle, status uint32) []byte {
	b := make([]byte, 24+4+21*n+4)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], uint32(n))
	off := 28
	for i := 0; i < n; i++ {
		putU32(b[off:off+4], 0)
		off += 4
		serviceNodeID(b[off:off+4], uint16(i+1)) // monitoredItemId
		off += 4
		binary.LittleEndian.PutUint64(b[off:off+8], 0)
		off += 8
		putU32(b[off:off+4], 1)
		off += 4
		b[off] = 0x00 // filterResult null
		off++
	}
	putU32(b[off:off+4], 0xFFFFFFFF)
	return b
}

// setPubModeRequestBody encodes SetPublishingModeRequest: RequestHeader(31)
// + publishingEnabled(1) + SubscriptionIds array (one id).
func setPubModeRequestBody(handle uint32) []byte {
	b := make([]byte, 40)
	putRequestHeader(b[0:31], handle)
	b[31] = 0x01 // publishingEnabled
	putU32(b[32:36], 1)
	putU32(b[36:40], 1) // subscriptionId
	return b
}

// setPubModeResponseBody encodes SetPublishingModeResponse: ResponseHeader
// (24) + results array of Boolean (one byte per element, not u32) + null
// diagnostic array.
func setPubModeResponseBody(handle, status uint32) []byte {
	b := make([]byte, 33)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], 1)
	b[28] = 0x01 // results[0]: true
	putU32(b[29:33], 0xFFFFFFFF)
	return b
}

// publishRequestBody encodes PublishRequest: RequestHeader(31) + null
// Acknowledgements array.
func publishRequestBody(handle uint32) []byte {
	b := make([]byte, 35)
	putRequestHeader(b[0:31], handle)
	putU32(b[31:35], 0xFFFFFFFF)
	return b
}

// publishResponseBody encodes PublishResponse: ResponseHeader(24) +
// subscriptionId(4) + null availableSequenceNumbers(4) + moreNotifications(1)
// + NotificationMessage(sequenceNumber(4) + publishTime(8) + notificationData
// array) + null results/diagnostic tail arrays. status == 0 appends a
// DataChangeNotification in notificationData[0] (ExtensionObject with TypeId
// FourByte NodeId 811 + binary body); the keep-alive publish uses an empty
// notificationData array.
func publishResponseBody(handle, status uint32) []byte {
	if status == 0 {
		// 24 hdr + 4 subId + 4 availSeq + 1 more + 4 seq + 8 time + 4
		// dataCount + 4 (ext obj TypeId) + 1 (encoding) + 4 (body len)
		// + 8 (DataChangeNotification body) + 4 + 4 (tail arrays) = 74.
		b := make([]byte, 74)
		putResponseHeader(b[0:24], handle, status)
		putU32(b[24:28], 1) // subscriptionId
		putU32(b[28:32], 0xFFFFFFFF)
		b[32] = 0x00                               // moreNotifications: false
		putU32(b[33:37], 1)                        // NotificationMessage.sequenceNumber
		binary.LittleEndian.PutUint64(b[37:45], 0) // publishTime
		putU32(b[45:49], 1)                        // notificationData count
		// ExtensionObject: TypeId FourByte NodeId 811, binary body.
		serviceNodeID(b[49:53], 811)
		b[53] = 0x01 // encoding: binary body follows
		putU32(b[54:58], 8)
		// DataChangeNotification: empty MonitoredItemNotifications array +
		// null diagnosticInfos array.
		putU32(b[58:62], 0)
		putU32(b[62:66], 0xFFFFFFFF)
		putU32(b[66:70], 0xFFFFFFFF) // results (per subscription) null
		putU32(b[70:74], 0xFFFFFFFF) // diagnosticInfos null
		return b
	}
	// Keep-alive: empty notificationData array. 24 hdr + 4 subId + 4 availSeq
	// + 1 more + 4 seq + 8 time + 4 dataCount + 4 results + 4 diagnostics.
	b := make([]byte, 57)
	putResponseHeader(b[0:24], handle, status)
	putU32(b[24:28], 1)
	putU32(b[28:32], 0xFFFFFFFF)
	b[32] = 0x00
	putU32(b[33:37], 2)
	binary.LittleEndian.PutUint64(b[37:45], 0)
	putU32(b[45:49], 0xFFFFFFFF)
	putU32(b[49:53], 0xFFFFFFFF)
	putU32(b[53:57], 0xFFFFFFFF)
	return b
}

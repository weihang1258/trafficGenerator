// Package openwire implements the ActiveMQ OpenWire terminal layer (B5)：
// TCP 载体上的 [4B length][1B type][commandId][responseRequired][fields]
// loose 编码（非 tight、非 cached——tshark 3.6.14 的解析口径）。builder.go
// 只做线格式编码（纯函数），事件折叠/状态机校验在 layer_gen.go。
//
// 编码对照 packet-openwire.c（Wireshark master，本机 tshark 3.6.14 同代）：
// 每字段按 dissector 的读取顺序与宽度原样产出，不写真实 ActiveMQ 的尾部
// BooleanStream（dissector 逐字段消费全部字节，多余尾字节会报
// "command fields unknown" Expert Info）。嵌套对象 [1B notNull][1B type]，
// 可空字符串 [1B notNull][2B len][bytes]，布尔/字节 1B 裸值，INTEGER 4B BE，
// LONG 8B BE，BYTE_ARRAY [1B notNull][4B len][bytes]。
package openwire

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// 线格式常量（packet-openwire.c 的 #define，即线上字节值）。
const (
	cmdWireFormatInfo = 1
	cmdConnectionInfo = 3
	cmdSessionInfo    = 4
	cmdConsumerInfo   = 5
	cmdProducerInfo   = 6
	cmdTransactionInfo = 7
	cmdShutdownInfo   = 11
	cmdRemoveInfo     = 12
	cmdMessageDispatch = 21
	cmdMessageAck     = 22
	cmdActiveMQMessage = 23
	cmdResponse       = 30
	cmdExceptionResponse = 31

	objActiveMQQueue            = 100 // 0x64
	objActiveMQTopic            = 101 // 0x65
	objMessageID                = 110 // 0x6e
	objLocalTransactionID       = 111 // 0x6f
	objConnectionID             = 120 // 0x78
	objSessionID                = 121 // 0x79
	objConsumerID               = 122 // 0x7a
	objProducerID               = 123 // 0x7b

	txnBegin    = 0
	txnPrepare  = 1
	txnCommit   = 2 // CommitOnePhase
	txnRollback = 4

	openWireMagic = "ActiveMQ"

	defaultDstPort = 61616
	// minCommandBytes 是 length 字段之后的最小字节数（1B type + 4B commandId
	// + 1B responseRequired）；WireFormatInfo 无 commandId 但 body ≥ 21。
	minCommandBytes = 6

	defaultVersion   = 12
	defaultAckMode   = "auto"
	defaultPrefetch  = 1000
	defaultPriority  = 4
	defaultMsgCount  = 1
)

// ackTypeByte maps the config ack_mode to the MessageAck acktype byte
// （ActiveMQ MessageAck ACK_TYPE：DELIVERED=0 / POISON=1 / STANDARD=2 /
// INDIVIDUAL=3 / PRESERVE_UNMATCHED=4? ——本生成器只用 0/2/3 三个档位，
// dups_ok 用 0（DELIVERED，JMS DUPS_OK 的 wire 语义档）。
func ackTypeByte(mode string) (byte, bool) {
	switch mode {
	case "", "auto":
		return 0, true
	case "client":
		return 2, true
	case "individual":
		return 3, true
	case "dups_ok":
		return 0, true
	}
	return 0, false
}

// destinationParts splits "queue://name" / "topic://name" into
// (typeByte, name)。其它前缀/空名拒绝。
func destinationParts(dest string) (byte, string, error) {
	switch {
	case strings.HasPrefix(dest, "queue://"):
		name := dest[len("queue://"):]
		if name == "" {
			return 0, "", fmt.Errorf("openwire: destination %q has an empty queue name", dest)
		}
		return objActiveMQQueue, name, nil
	case strings.HasPrefix(dest, "topic://"):
		name := dest[len("topic://"):]
		if name == "" {
			return 0, "", fmt.Errorf("openwire: destination %q has an empty topic name", dest)
		}
		return objActiveMQTopic, name, nil
	default:
		return 0, "", fmt.Errorf("openwire: destination %q is invalid — want queue://name or topic://name", dest)
	}
}

// ---- primitive encoders（对照 dissect_openwire_type 的读取规则）----

// putNull writes the single not-null byte 0x00 (a NULL optional object/string)。
func putNull(b []byte) []byte { return append(b, 0x00) }

// putString writes a nullable loose string: [notNull][2B len][utf8]；空串以
// NULL 编码（notNull=0）。
func putString(b []byte, s string) []byte {
	if s == "" {
		return putNull(b)
	}
	b = append(b, 0x01)
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// putObject writes [notNull=1][objectType][fields]。
func putObject(b []byte, objType byte, fields []byte) []byte {
	b = append(b, 0x01, objType)
	return append(b, fields...)
}

// connectionIDFields is the ConnectionId body: value STRING (nullable)。
func connectionIDFields(value string) []byte {
	return putString(nil, value)
}

// sessionIDFields is the SessionId body: connectionId STRING (nullable) +
// value LONG。
func sessionIDFields(conn string, value uint64) []byte {
	b := putString(nil, conn)
	return binary.BigEndian.AppendUint64(b, value)
}

// consumerProducerIDFields is the ConsumerId/ProducerId body: connectionId
// STRING + value LONG + sessionId LONG。
func consumerProducerIDFields(conn string, value, session uint64) []byte {
	b := putString(nil, conn)
	b = binary.BigEndian.AppendUint64(b, value)
	return binary.BigEndian.AppendUint64(b, session)
}

// messageIDFields is the MessageId body: producerId CACHED (nullable) +
// producerSequenceId LONG + brokerSequenceId LONG。
func messageIDFields(conn string, producerValue, session, producerSeq, brokerSeq uint64) []byte {
	b := putObject(nil, objProducerID, consumerProducerIDFields(conn, producerValue, session))
	b = binary.BigEndian.AppendUint64(b, producerSeq)
	return binary.BigEndian.AppendUint64(b, brokerSeq)
}

// localTransactionIDFields is the LocalTransactionId body: value LONG +
// connectionId CACHED (nullable)。
func localTransactionIDFields(value uint64, conn string) []byte {
	b := binary.BigEndian.AppendUint64(nil, value)
	return putObject(b, objConnectionID, connectionIDFields(conn))
}

// destinationFields is the ActiveMQQueue/Topic body: name STRING (nullable)。
func destinationFields(name string) []byte {
	return putString(nil, name)
}

// emptyBrokerPath is an OBJECT_ARRAY with zero elements: [notNull=1][00 00]。
func emptyBrokerPath(b []byte) []byte {
	return append(b, 0x01, 0x00, 0x00)
}

// ---- command builders ----

// frameCommand prefixes the [4B length][1B type][cmdId][respReq] header onto
// the already-encoded fields。length = type(1) + cmdId(4) + respReq(1) +
// len(fields)，与 get_openwire_pdu_len（ntohl(offset)+4）一致。
func frameCommand(cmdType byte, commandID uint32, responseRequired bool, fields []byte) []byte {
	rr := byte(0)
	if responseRequired {
		rr = 1
	}
	body := make([]byte, 0, 6+len(fields))
	body = append(body, cmdType)
	body = binary.BigEndian.AppendUint32(body, commandID)
	body = append(body, rr)
	body = append(body, fields...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(out, body...)
}

// frameRaw prefixes [4B length][1B type] without the commandId header
//（WireFormatInfo 专用）。
func frameRaw(cmdType byte, fields []byte) []byte {
	body := append([]byte{cmdType}, fields...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(out, body...)
}

// BuildWireFormatInfo encodes the negotiation command: 8B magic + 4B version
// + 1B data（tight/cache 位，本版恒 0）+ 4B properties length + MAP（4B count
// + entries）。空 properties = [4] + [0]，与 dissector 的
// wireformatinfo_length + MAP count 两段读取一一对应。
func BuildWireFormatInfo(version int) []byte {
	fields := make([]byte, 0, 21)
	fields = append(fields, openWireMagic...)
	fields = binary.BigEndian.AppendUint32(fields, uint32(version))
	fields = append(fields, 0x00) // data byte: tight/cache 均未置位
	fields = binary.BigEndian.AppendUint32(fields, 4) // properties 字节长
	fields = binary.BigEndian.AppendUint32(fields, 0) // MAP count = 0
	return frameRaw(cmdWireFormatInfo, fields)
}

// buildConnectionInfoFields encodes the ConnectionInfo fields（顺序 =
// dissector：connectionid/clientid/password/username/brokerpath/4×BOOL…）。
func buildConnectionInfoFields(e *core.OpenWireEvent, connID string) []byte {
	b := putObject(nil, objConnectionID, connectionIDFields(connID))
	b = putString(b, connID) // clientid：沿用连接标识，非空可断言
	b = putNull(b)           // password
	b = putNull(b)           // username
	b = emptyBrokerPath(b)
	b = append(b, 0x00) // brokerMasterConnector
	b = append(b, 0x00) // manageable
	b = append(b, 0x00) // clientMaster
	b = append(b, 0x00) // faultTolerant
	b = append(b, 0x00) // failoverReconnect
	return b
}

// buildSessionInfoFields: sessionid CACHED。
func buildSessionInfoFields(e *core.OpenWireEvent, connID string) []byte {
	return putObject(nil, objSessionID, sessionIDFields(connID, e.SessionID))
}

// buildProducerInfoFields: producerid CACHED + destination CACHED +
// brokerpath + dispatchasync + windowsize。
func buildProducerInfoFields(e *core.OpenWireEvent, connID string) ([]byte, error) {
	objType, name, err := destinationParts(e.Destination)
	if err != nil {
		return nil, err
	}
	b := putObject(nil, objProducerID, consumerProducerIDFields(connID, e.ProducerID, e.SessionID))
	b = putObject(b, objType, destinationFields(name))
	b = emptyBrokerPath(b)
	b = append(b, 0x00)                            // dispatchasync
	b = binary.BigEndian.AppendUint32(b, 0)        // windowsize
	return b, nil
}

// buildConsumerInfoFields: 18 fields per the dissector order.
func buildConsumerInfoFields(e *core.OpenWireEvent, connID string) ([]byte, error) {
	objType, name, err := destinationParts(e.Destination)
	if err != nil {
		return nil, err
	}
	prefetch := e.Prefetch
	if prefetch == 0 {
		prefetch = defaultPrefetch
	}
	b := putObject(nil, objConsumerID, consumerProducerIDFields(connID, e.ConsumerID, e.SessionID))
	b = append(b, 0x00) // browser
	b = putObject(b, objType, destinationFields(name))
	b = binary.BigEndian.AppendUint32(b, uint32(prefetch)) // prefetchsize
	b = binary.BigEndian.AppendUint32(b, 0)                // maximumpendingmessagelimit
	b = append(b, 0x00)                                    // dispatchasync
	b = putNull(b)                                         // selector
	b = putNull(b)                                         // subscriptionname
	b = append(b, 0x00)                                    // nolocal
	b = append(b, 0x00)                                    // exclusive
	b = append(b, 0x00)                                    // retroactive
	b = putNull(b)                                         // priority（BYTE nullable）
	b = emptyBrokerPath(b)
	b = putNull(b) // additionalpredicate（NESTED nullable）
	b = append(b, 0x00) // networksubscription
	b = append(b, 0x00) // optimizedacknowledge
	b = append(b, 0x00) // norangeacks
	b = emptyBrokerPath(b)
	return b, nil
}

// buildMessageFields encodes the 29 Message fields in dissector order.
// content 为 [notNull][4B len][bytes]（ActiveMQMessage 23 的 body 保持不透明
// 字节；TextMessage/BytesMessage 会被 dissector 二次解析并可能报
// body_type_not_supported Expert Info，故只产 23）。
func buildMessageFields(e *core.OpenWireEvent, connID string, msgSeq uint64, txID uint64, hasTx bool) ([]byte, error) {
	objType, name, err := destinationParts(e.Destination)
	if err != nil {
		return nil, err
	}
	body := e.BodyB64
	if body == nil && e.Body != "" {
		body = []byte(e.Body)
	}
	priority := e.Priority
	if priority == 0 {
		priority = defaultPriority
	}

	b := putObject(nil, objProducerID, consumerProducerIDFields(connID, e.ProducerID, e.SessionID))
	b = putObject(b, objType, destinationFields(name))
	if hasTx {
		b = putObject(b, objLocalTransactionID, localTransactionIDFields(txID, connID))
	} else {
		b = putNull(b) // transactionid
	}
	b = putNull(b) // originaldestination
	b = putObject(b, objMessageID, messageIDFields(connID, e.ProducerID, e.SessionID, msgSeq, 0))
	b = putNull(b) // originaltransactionid
	b = putNull(b) // groupid
	b = binary.BigEndian.AppendUint32(b, 0) // groupsequence
	b = putNull(b) // correlationid
	b = append(b, boolByte(e.Persistent))   // persistent
	b = binary.BigEndian.AppendUint64(b, 0) // expiration
	b = append(b, byte(priority))           // priority（BYTE 非空裸值）
	b = putNull(b)                          // replyto
	b = binary.BigEndian.AppendUint64(b, 0) // timestamp
	b = putNull(b)                          // type
	if len(body) > 0 {
		b = append(b, 0x01)
		b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
		b = append(b, body...)
	} else {
		b = putNull(b) // content（空 body 合法：null 数组）
	}
	b = putNull(b)                          // marshalledProperties
	b = putNull(b)                          // datastructure（COMMAND_INNER）
	b = putNull(b)                          // targetconsumerid
	b = append(b, 0x00)                     // compressed
	b = binary.BigEndian.AppendUint32(b, 0) // redeliverycounter
	b = emptyBrokerPath(b)
	b = binary.BigEndian.AppendUint64(b, 0) // arrival
	b = putNull(b)                          // userid
	b = append(b, 0x00)                     // receivedbyDFBridge
	b = append(b, 0x00)                     // droppable
	b = emptyBrokerPath(b)
	b = binary.BigEndian.AppendUint64(b, 0) // brokerInTime
	b = binary.BigEndian.AppendUint64(b, 0) // brokerOutTime
	return b, nil
}

// buildMessageDispatchFields: consumerid CACHED + destination CACHED +
// message NESTED + redeliverycounter。嵌套 Message 是 NESTED 对象：
// [notNull][type=23][cmdId 4B][respReq 1B][Message 字段]——dissector 的
// type-23 复杂分支自己读 commandId/responseRequired（裸值），没有 4B 长度
// 前缀也没有第二个 type 字节（frameCommand 的帧头只属于顶层命令）。
func buildMessageDispatchFields(e *core.OpenWireEvent, connID string, msgSeq uint64, msgCmdID uint32) ([]byte, error) {
	objType, name, err := destinationParts(e.Destination)
	if err != nil {
		return nil, err
	}
	fields, err := buildMessageFields(e, connID, msgSeq, 0, false)
	if err != nil {
		return nil, err
	}
	inner := binary.BigEndian.AppendUint32(nil, msgCmdID)
	inner = append(inner, 0x00) // responseRequired：broker 侧 dispatch 无需响应
	inner = append(inner, fields...)
	b := putObject(nil, objConsumerID, consumerProducerIDFields(connID, e.ConsumerID, e.SessionID))
	b = putObject(b, objType, destinationFields(name))
	b = putObject(b, cmdActiveMQMessage, inner)
	b = binary.BigEndian.AppendUint32(b, uint32(e.Redelivery))
	return b, nil
}

// buildMessageAckFields: destination CACHED + transactionid CACHED (null) +
// consumerid CACHED + acktype BYTE + first/last messageid NESTED +
// messagecount INTEGER。
func buildMessageAckFields(e *core.OpenWireEvent, connID string, msgSeq uint64) ([]byte, error) {
	objType, name, err := destinationParts(e.Destination)
	if err != nil {
		return nil, err
	}
	ackType, ok := ackTypeByte(e.AckMode)
	if !ok {
		return nil, fmt.Errorf("openwire: unknown ack_mode %q", e.AckMode)
	}
	count := e.MessageCount
	if count == 0 {
		count = defaultMsgCount
	}
	b := putObject(nil, objType, destinationFields(name))
	b = putNull(b) // transactionid
	b = putObject(b, objConsumerID, consumerProducerIDFields(connID, e.ConsumerID, e.SessionID))
	b = append(b, ackType)
	// first/last messageid 引用被确认消息的 MessageId：producer 值由生成器
	// 解析目标消息后写入 e.ProducerID（fixture 关联键一致性）。
	b = putObject(b, objMessageID, messageIDFields(connID, e.ProducerID, e.SessionID, msgSeq, 0))
	b = putObject(b, objMessageID, messageIDFields(connID, e.ProducerID, e.SessionID, msgSeq, 0))
	b = binary.BigEndian.AppendUint32(b, uint32(count))
	return b, nil
}

// buildTransactionInfoFields: connectionid CACHED + transactionid CACHED
//（LocalTransactionId）+ type BYTE。
func buildTransactionInfoFields(e *core.OpenWireEvent, connID string) ([]byte, error) {
	txn := e.Transaction
	if txn == nil {
		return nil, fmt.Errorf("openwire: transaction event requires a transaction block")
	}
	var t byte
	switch txn.Kind {
	case "begin":
		t = txnBegin
	case "prepare":
		t = txnPrepare
	case "commit":
		t = txnCommit
	case "rollback":
		t = txnRollback
	default:
		return nil, fmt.Errorf("openwire: unknown transaction kind %q (want begin|prepare|commit|rollback)", txn.Kind)
	}
	b := putObject(nil, objConnectionID, connectionIDFields(connID))
	b = putObject(b, objLocalTransactionID, localTransactionIDFields(txn.ID, connID))
	b = append(b, t)
	return b, nil
}

// buildResponseFields: correlationid INTEGER（裸 4B）。
func buildResponseFields(correlationID uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, correlationID)
}

// buildExceptionResponseFields: correlationid INTEGER + exception THROWABLE
//（class/message 字符串 + 栈深 0）。
func buildExceptionResponseFields(correlationID uint32, message string) []byte {
	b := binary.BigEndian.AppendUint32(nil, correlationID)
	b = putString(b, "java.lang.IllegalStateException") // class
	b = putString(b, message)                           // message
	b = binary.BigEndian.AppendUint16(b, 0)             // stackTraceDepth
	return b
}

// buildRemoveInfoFields: objectid CACHED（ConsumerId/ProducerId/SessionId/
// ConnectionId 按 id 优先级）+ lastdeliveredsequenceid LONG。
func buildRemoveInfoFields(e *core.OpenWireEvent, connID string) []byte {
	var objType byte
	var body []byte
	switch {
	case e.ConsumerID != 0:
		objType = objConsumerID
		body = consumerProducerIDFields(connID, e.ConsumerID, e.SessionID)
	case e.SessionID != 0:
		objType = objSessionID
		body = sessionIDFields(connID, e.SessionID)
	default:
		objType = objConnectionID
		body = connectionIDFields(connID)
	}
	b := putObject(nil, objType, body)
	b = binary.BigEndian.AppendUint64(b, 0) // lastdeliveredsequenceid
	return b
}

// boolByte maps a bool to its wire byte (0/1)。
func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// messageSeqOf derives the wire producer-sequence id for a logical message
// key: trailing digit run "m7" → 7、"key-42" → 42；无数字尾巴 → 0（断言走
// 消息关联而非具体序号）。
func messageSeqOf(key string) uint64 {
	i := len(key)
	for i > 0 && key[i-1] >= '0' && key[i-1] <= '9' {
		i--
	}
	if i == len(key) {
		return 0
	}
	n, err := strconv.ParseUint(key[i:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

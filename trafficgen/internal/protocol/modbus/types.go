// Package modbus implements the Modbus TCP protocol planner.
// This file contains type definitions and constants.
package modbus

// Modbus function codes (功能码) per MB-ASYM-TCP §6.
const (
	FCReadCoils                uint8 = 0x01 // Read Coils (读线圈)
	FCReadDiscreteInputs       uint8 = 0x02 // Read Discrete Inputs (读离散输入)
	FCReadHoldingRegisters     uint8 = 0x03 // Read Holding Registers (读保持寄存器)
	FCReadInputRegisters       uint8 = 0x04 // Read Input Registers (读输入寄存器)
	FCWriteSingleCoil          uint8 = 0x05 // Write Single Coil (写单线圈)
	FCWriteSingleRegister      uint8 = 0x06 // Write Single Register (写单寄存器)
	FCReadExceptionStatus      uint8 = 0x07 // Read Exception Status (读异常状态)
	FCDiagnostic               uint8 = 0x08 // Diagnostic (诊断)
	FCGetCommEventCounter      uint8 = 0x0B // Get Comm Event Counter (取通信事件计数)
	FCGetCommEventLog          uint8 = 0x0C // Get Comm Event Log (取通信事件日志)
	FCWriteMultipleCoils       uint8 = 0x0F // Write Multiple Coils (写多线圈)
	FCWriteMultipleRegisters   uint8 = 0x10 // Write Multiple Registers (写多寄存器)
	FCReportServerID           uint8 = 0x11 // Report Server ID (报告服务器 ID)
	FCReadFileRecords          uint8 = 0x14 // Read File Records (读文件记录)
	FCWriteFileRecords         uint8 = 0x15 // Write File Records (写文件记录)
	FCMaskWriteRegister        uint8 = 0x16 // Mask Write Register (掩码写寄存器)
	FCReadWriteMultipleRegs    uint8 = 0x17 // Read/Write Multiple Registers (读写多寄存器)
	FCReadFIFOQueue            uint8 = 0x18 // Read FIFO Queue (读 FIFO 队列)
	FCEncapsulatedInterface    uint8 = 0x2B // Encapsulated Interface Transport (封装接口传输)
)

// Exception codes (异常码) per MB-ASYM-TCP §7.
const (
	ExcIllegalFunction         uint8 = 0x01 // Illegal Function (非法功能)
	ExcIllegalDataAddress      uint8 = 0x02 // Illegal Data Address (非法数据地址)
	ExcIllegalDataValue        uint8 = 0x03 // Illegal Data Value (非法数据值)
	ExcSlaveDeviceFailure      uint8 = 0x04 // Slave Device Failure (从站设备故障)
	ExcAcknowledge             uint8 = 0x05 // Acknowledge (确认)
	ExcSlaveDeviceBusy         uint8 = 0x06 // Slave Device Busy (从站忙)
	ExcNegativeAcknowledge     uint8 = 0x07 // Negative Acknowledge (否定确认)
	ExcMemoryParityError       uint8 = 0x08 // Memory Parity Error (内存奇偶校验错)
	ExcGatewayPathUnavailable  uint8 = 0x0A // Gateway Path Unavailable (网关路径不可用)
	ExcGatewayTargetNoResponse uint8 = 0x0B // Gateway Target Device Failed to Respond (网关目标设备无响应)
)

// Diagnostic sub-function codes (诊断子功能码) per MB-ASYM-TCP §6.8.
const (
	DiagReturnQueryData            uint16 = 0x0000 // Return Query Data (返回查询数据)
	DiagRestartCommunications      uint16 = 0x0001 // Restart Communications (重启通信)
	DiagReturnDiagnosticRegister   uint16 = 0x0002 // Return Diagnostic Register (返回诊断寄存器)
	DiagChangeASCIIInputDelimiter  uint16 = 0x0003 // Change ASCII Input Delimiter (修改 ASCII 输入分隔符)
	DiagForceListenOnlyMode        uint16 = 0x0004 // Force Listen Only Mode (强制只听模式)
	DiagClearCounters              uint16 = 0x000A // Clear Counters and Diagnostic Register (清计数器与诊断寄存器)
	DiagReturnBusMessageCount      uint16 = 0x000B // Return Bus Message Count (返回总线报文计数)
	DiagReturnBusCommErrorCount    uint16 = 0x000C // Return Bus Communication Error Count (返回总线通信错误计数)
	DiagReturnBusExceptionErrorCnt uint16 = 0x000D // Return Bus Exception Error Count (返回总线异常错误计数)
	DiagReturnSlaveMessageCount    uint16 = 0x000E // Return Slave Message Count (返回从站报文计数)
	DiagReturnSlaveNoResponseCount uint16 = 0x000F // Return Slave No Response Count (返回从站无响应计数)
	DiagReturnSlaveNAKCount        uint16 = 0x0010 // Return Slave NAK Count (返回从站 NAK 计数)
	DiagReturnSlaveBusyCount       uint16 = 0x0011 // Return Slave Busy Count (返回从站忙计数)
	DiagReturnBusCharOverrunCount  uint16 = 0x0012 // Return Bus Character Overrun Count (返回总线字符溢出计数)
	DiagClearOverrunCounter        uint16 = 0x0014 // Clear Overrun Counter and Flag (清溢出计数器与标志)
	DiagGetClearModbusPlusStats    uint16 = 0x0015 // Get/Clear Modbus Plus Statistics (获取/清空 Modbus Plus 统计)
)

// MEI Type codes (MEI 类型码) per MB-ASYM-TCP §6.21.
const (
	MEITypeCANopenGeneral        uint8 = 0x0D // CANopen General (CiA 309, not implemented)
	MEITypeReadDeviceIdentification uint8 = 0x0E // Read Device Identification (读设备标识)
)

// Read Device ID Code values per MB-ASYM-TCP §6.21.
const (
	ReadDeviceIDCodeBasic    uint8 = 0x01 // Basic
	ReadDeviceIDCodeRegular  uint8 = 0x02 // Regular
	ReadDeviceIDCodeExtended uint8 = 0x03 // Extended
	ReadDeviceIDCodeSpecific uint8 = 0x04 // Specific
)

// Conformity Level values per MB-ASYM-TCP §6.21.
const (
	ConformityBasic             uint8 = 0x01 // Basic
	ConformityRegular           uint8 = 0x02 // Regular
	ConformityExtended          uint8 = 0x03 // Extended
	ConformityBasicPrivate      uint8 = 0x81 // Basic + Private
	ConformityRegularPrivate    uint8 = 0x82 // Regular + Private
	ConformityExtendedPrivate   uint8 = 0x83 // Extended + Private
)

// Quantity limits per §2.7.
const (
	MaxCoilsQuantity       = 2000 // FC 0x01/0x02
	MaxRegistersQuantity   = 125  // FC 0x03/0x04/0x17 read
	MaxWriteCoilsQuantity  = 1968 // FC 0x0F
	MaxWriteRegsQuantity   = 123  // FC 0x10
	MaxWriteMultipleQty    = 121  // FC 0x17 write
	MaxFIFOCount           = 31   // FC 0x18
)

// MBAP header field offsets (MBAP 头部字段偏移).
const (
	MBAPTxnIDOffset   = 0 // Transaction ID offset (2 bytes)
	MBAPProtoIDOffset = 2 // Protocol ID offset (2 bytes)
	MBAPLengthOffset  = 4 // Length offset (2 bytes)
	MBAPUnitIDOffset  = 6 // Unit ID offset (1 byte)
)

// Exception response mask (异常响应掩码).
const ExceptionMask uint8 = 0x80

// PDU offsets for common fields.
const (
	PDUFCOffset        = 0 // Function Code offset
	PDUAddrOffset      = 1 // Starting Address offset (2 bytes)
	PDUQtyOffset       = 3 // Quantity offset (2 bytes)
	PDUByteCountOffset = 5 // Byte Count offset (1 byte, except FC 0x18)
)

// ExceptionResponseFC returns the exception response function code.
// Per §3.4, exception FC = original FC | 0x80.
// For FCs with bit7 already set (exemption path), this is idempotent.
func ExceptionResponseFC(fc uint8) uint8 {
	return fc | ExceptionMask
}

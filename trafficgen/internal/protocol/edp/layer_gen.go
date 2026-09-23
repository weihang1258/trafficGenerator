// Package edp — OneNET Enhanced Device Protocol (TCP-based byte-stream terminal).
//
// Register* functions run at init() time, wiring the edp layer into the
// chain planner and generator factory. The side-effect import
// _ "…/protocol/edp" activates this registration.
//
// EDP = [ip → tcp → edp] (tcp-only 族；DependsOn ["tcp"]；FieldContract
// tcp.dst_port=4472)。
package edp
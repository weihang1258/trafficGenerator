// Package xmrmining — Monero/RandomX stratum 行式 JSON 终结层。
//
// Register* functions run at init() time (in builder.go), wiring the
// xmrmining layer into the chain planner and generator factory. The
// side-effect import _ "…/protocol/xmrmining" activates this registration.
//
// XMR = [ip → tcp → xmrmining]（tcp-only 族；DependsOn ["tcp"]；
// FieldContract tcp.dst_port=18081）。
package xmrmining

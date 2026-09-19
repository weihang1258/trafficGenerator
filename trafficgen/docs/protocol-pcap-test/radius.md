# radius Pcap Test Results

Cases: 25 — pass 25, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| radius_acct_1813 | T-RADIUS-4 Accounting-Request→1813（translate 顺序修正：dst 缺席依 code==4?1813:1812 覆盖 :770 预写；code4→auto resp 5 Accounting-Response；参考 start-stop.pcap） | pass | 2 | [pcap](radius/radius_acct_1813.pcap) |
| radius_attr_boundary | T-RADIUS-23 普通 attr 恰 253B 边界等值通过（§9.8 边界格：253 过/254 拒由 T-16 对偶） | pass | 2 | [pcap](radius/radius_attr_boundary.pcap) |
| radius_attr_formats | T-RADIUS-15 属性四 format+VSA 枚举格（string/ipv4/uint32/hex+VSA vendor_id 9；9.20-9.22 双列表 attributes/response_attributes 各≥1 格） | pass | 2 | [pcap](radius/radius_attr_formats.pcap) |
| radius_auth_fixed | T-RADIUS-12 fixed authenticator 钉值（16B hex 请求帧 radius.authenticator 值断言=唯一可钉值格；响应侧 nonzero 恒随机） | pass | 2 | [pcap](radius/radius_auth_fixed.pcap) |
| radius_challenge | T-RADIUS-5 code11 Access-Challenge 显式响应（3/11 无 auto 必须显式合同；challenge 11→rsp 11） | pass | 2 | [pcap](radius/radius_challenge.pcap) |
| radius_code3 | T-RADIUS-7 请求码 3 枚举格（requestCodes 含 3=legacy 合同，无 auto→显式 response_code:3=Access-Reject） | pass | 2 | [pcap](radius/radius_code3.pcap) |
| radius_default_port | T-RADIUS-20 radius 层端口全缺→dst=1812（translate 顺序修正 code1→1812 覆盖路径；src 0 上包=worker/缺省缺省） | pass | 2 | [pcap](radius/radius_default_port.pcap) |
| radius_flat_presence | T-RADIUS-2 presence 判死（层链+顶层 radius 子映射并存即拒，空 map 也死——判死负例非残留，记忆文档 presence-negative-case-shape） | pass | 0 | [pcap]() |
| radius_flat_static_port | T-RADIUS-3 radius 层静态四元组+flows=2 拒（12.9，多流必须动态对象） | pass | 0 | [pcap]() |
| radius_nas_combo | T-RADIUS-24 现网接入认证组合例（§9.10：Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性承载；MA 仅 opaque 字节承载） | pass | 2 | [pcap](radius/radius_nas_combo.pcap) |
| radius_neg_attr_len | T-RADIUS-16 负例：string 254B 超 253 门（MaxAttrValue） | pass | 0 | [pcap]() |
| radius_neg_auth_hex | T-RADIUS-13 负例：authenticator 非法 hex | pass | 0 | [pcap]() |
| radius_neg_auth_len | T-RADIUS-14 负例：authenticator 15B hex→16 字节门 | pass | 0 | [pcap]() |
| radius_neg_coa | T-RADIUS-25 负例：CoA-Request(43) 白名单外拒（RFC 5176 现网真实码，比 T-10 假码 42 更现网；CoA 族支持=B′ 立项） | pass | 0 | [pcap]() |
| radius_neg_format | T-RADIUS-17 负例：format dword 非法 | pass | 0 | [pcap]() |
| radius_neg_no_auto | T-RADIUS-9 负例：code3 无 response_code→无默认响应拒（task-time） | pass | 0 | [pcap]() |
| radius_neg_reqcode | T-RADIUS-10 负例：code42 非法请求码 | pass | 0 | [pcap]() |
| radius_neg_rspcode | T-RADIUS-11 负例：response_code:9 非法响应码 | pass | 0 | [pcap]() |
| radius_neg_vsa_len | T-RADIUS-22 负例：VSA value 248B 超 247 门（MaxVSAValue=8+value≤255；§9.8 超长×VSA 位型格） | pass | 0 | [pcap]() |
| radius_port_dyn | T-RADIUS-21 src_port/dst_port 动态 inc+flows=2（E1 逐流端口池；group_id 固定同 worker 保序；2 流×2=4 包） | pass | 4 | [pcap](radius/radius_port_dyn.pcap) |
| radius_reject | T-RADIUS-8 Access-Request 被拒失败分支（code1+response_code:3→Access-Reject；3.7/9.9 失败分支面） | pass | 2 | [pcap](radius/radius_reject.pcap) |
| radius_rounds | T-RADIUS-18 rounds:3+identifier:5→6 包，radius.id 5/6/7 递增（identifier+round 合同；9.39 rounds>256 回绕避开） | pass | 6 | [pcap](radius/radius_rounds.pcap) |
| radius_smoke_01 | 冒烟（改写）：[ip,radius] 空业务面→1 轮 req(up)/rsp(down) 2 包。端口显式化 12345/1812（worker/缺省显式化，mpls 轮先例）；code1→2 auto、id 0 复刻、length 26/20、authenticator nonzero 全保留等价 | pass | 2 | [pcap](radius/radius_smoke_01.pcap) |
| radius_status | T-RADIUS-6 Status-Server 探询对（code12→auto 13 Status-Client，RFC 5997） | pass | 2 | [pcap](radius/radius_status.pcap) |
| radius_v6 | T-RADIUS-19 IPv6 链同构（9.24 地址族对称，Validate 无族强制） | pass | 2 | [pcap](radius/radius_v6.pcap) |

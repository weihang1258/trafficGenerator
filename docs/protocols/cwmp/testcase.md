# CWMP（TR-069）测试用例契约

> 版本：v2.3.0（现状对账）  日期：2026-10-01
> 机器契约：`trafficgen/test/protocol_pcap/cases/cwmp.json`
> 状态：JSON 实测 153 条，110 正例、43 负例；本文按当前 JSON 对账，不沿用旧规划 ID。

## 1. 测试原则

每条 case 的 `spec_json` 都是可直接提交的任务配置：严格层链为 `[ip,tcp,http,cwmp]`，地址在 `ip`、端口在 `tcp`、协议字段在 `cwmp`。正例断言可观察输出（包数、握手、终止及必要字段）；负例必须由任务错误传播并包含 `error_contains` 锚词，不接受成功/0 包替代。

覆盖按规范行为面拆分：SOAP 1.1、HTTP POST/204、Inform 首事务、RPC 请求响应、Fault、Digest/Connection Request、IPv4/IPv6、多会话/并发、Download/Upload 流关联、事件码、字段上下界、XML/HTTP 线格式和配置拒绝。TCP 分段边界不作为 SOAP 消息边界；大报文以重组后的 Content-Length/实体断言。

## 2. 机器清单与分类

JSON 的 153 个 ID 是唯一清单。脚本对账结果：

- 正例 110：Inform/事件与参数事务、Fault、对象与传输 RPC、Digest/CR、并发和多会话、边界字段，以及 `cwmp_empty_layer_baseline` P0b 缺省流。
- 负例 43：`cwmp_neg_*` 领域错误，以及 `cwmp_pres_kill_neg` 顶层配置 presence 拒绝、`cwmp_v9_unknown_field_neg` 层字段白名单拒绝。
- 正例 `spec_json` 顶层键集合只有 `layers`；负例也保持层链输入，除 `cwmp_pres_kill_neg` 故意带顶层 `cwmp` 验证旧形状被拒。

### 2.1 正例 ID（110）

```text
cwmp_inform_ipv4_2p
cwmp_inform_paramlist_empty
cwmp_inform_event_bootstrap
cwmp_get_param_names_values
cwmp_set_parameter_values_single
cwmp_get_parameter_names_empty_response
cwmp_get_parameter_values_empty_response
cwmp_connection_request_auth_challenge
cwmp_inform_ipv6
cwmp_multi_session_sequential
cwmp_set_parameter_attributes
cwmp_get_parameter_attributes
cwmp_get_rpc_methods_cpe_to_acs
cwmp_soap_fault_acs
cwmp_http_keepalive_multi_transaction
cwmp_inform_14_event_codes
cwmp_multi_session_per_session_events
cwmp_mss_large_soap_200_params
cwmp_add_object
cwmp_delete_object
cwmp_factory_reset
cwmp_request_download
cwmp_kicked_method
cwmp_reboot_command_key_match
cwmp_download_flow_correlation
cwmp_autonomous_transfer_complete
cwmp_transfer_complete_success
cwmp_transfer_complete_fault
cwmp_upload
cwmp_schedule_download
cwmp_schedule_upload
cwmp_inform_paramlist_present
cwmp_event_value_change_batch
cwmp_event_vckcr_batch
cwmp_event_tc_mdownload
cwmp_acs_request_shape_a_cpe_post
cwmp_set_parameter_values_fault_multi
cwmp_acs_fault_8000 cwmp_acs_fault_8001 cwmp_acs_fault_8002
cwmp_acs_fault_8003 cwmp_acs_fault_8004 cwmp_acs_fault_8005
cwmp_acs_fault_8006 cwmp_acs_fault_8800 cwmp_acs_fault_8801
cwmp_acs_fault_8802 cwmp_acs_fault_8803 cwmp_acs_fault_8804
cwmp_acs_fault_8805
cwmp_cpe_fault_9000 cwmp_cpe_fault_9001 cwmp_cpe_fault_9002
cwmp_cpe_fault_9003 cwmp_cpe_fault_9004 cwmp_cpe_fault_9005
cwmp_cpe_fault_9006 cwmp_cpe_fault_9007 cwmp_cpe_fault_9008
cwmp_cpe_fault_9009 cwmp_cpe_fault_9010 cwmp_cpe_fault_9011
cwmp_cpe_fault_9012 cwmp_cpe_fault_9013 cwmp_cpe_fault_9014
cwmp_vendor_fault_9800 cwmp_vendor_fault_9801 cwmp_vendor_fault_9802
cwmp_vendor_fault_9803 cwmp_vendor_fault_9804 cwmp_vendor_fault_9805
cwmp_vendor_fault_9806 cwmp_vendor_fault_9807 cwmp_vendor_fault_9808
cwmp_vendor_fault_9809 cwmp_vendor_fault_9810 cwmp_vendor_fault_9811
cwmp_vendor_fault_9812 cwmp_vendor_fault_9813 cwmp_vendor_fault_9814
cwmp_vendor_fault_9815
cwmp_concurrent_sessions_2 cwmp_concurrent_with_interleaved_acs
cwmp_cr_401_no_authorized cwmp_mustunderstand_one cwmp_empty_response_204
cwmp_soap_action_empty_value cwmp_digest_qop_auth_known_vector
cwmp_oui_six_uppercase_hex cwmp_fault_8005_resend_inform
cwmp_inform_8002_terminate cwmp_inform_paramlist_explicit_empty
cwmp_event_array_64 cwmp_param_name_256_upper cwmp_manufacturer_64_upper
cwmp_command_key_32_upper cwmp_cr_username_percent cwmp_oui_001122_upper
cwmp_reboot_response_inform_pair cwmp_kicked_command_key_match
cwmp_download_command_key_match cwmp_3_session_sequential
cwmp_3_session_concurrent cwmp_set_parameter_values_empty_body
cwmp_get_parameter_attributes_empty_response cwmp_change_du_state_vc
cwmp_diag_complete_event cwmp_request_download_event
cwmp_download_file_size_1mb cwmp_empty_layer_baseline
```

### 2.2 负例 ID（43）与锚词

```text
cwmp_neg_envelope_soap12: namespace
cwmp_neg_invalid_event_code: value
cwmp_neg_id_mismatch: id
cwmp_neg_param_name_too_long: length
cwmp_neg_oui_lowercase: not six uppercase hex digits
cwmp_neg_acs_request_in_acs_cr: session
cwmp_neg_unknown_kind: unknown kind
cwmp_neg_oui_short: value
cwmp_neg_mdownload_no_tc: 7 TRANSFER COMPLETE
cwmp_neg_bootstrap_and_boot: value
cwmp_neg_flow_bad_session: correlation
cwmp_neg_http_method_get: method
cwmp_neg_soap_action_nonempty: SOAPAction
cwmp_neg_content_type_wrong: Content-Type
cwmp_neg_content_length_mismatch: Content-Length
cwmp_neg_envelope_namespace_wrong: envelope
cwmp_neg_invalid_fault_code: value
cwmp_neg_invalid_file_type: file type
cwmp_neg_raw_body_invalid_xml: envelope
cwmp_neg_flow_bad_anchor: correlation
cwmp_neg_unknown_profile: profile
cwmp_neg_param_key_too_long: length
cwmp_neg_unknown_acs_method: method
cwmp_neg_empty_post_before_inform: inform
cwmp_neg_uri_too_long: uri
cwmp_neg_empty_ok_204_unknown: unknown kind
cwmp_neg_empty_response_first: no pending
cwmp_neg_manufacturer_too_long: length
cwmp_neg_tc_without_issued: command key
cwmp_neg_delay_out_of_range: delay_seconds
cwmp_neg_cr_outside_acs_cr: acs_cr
cwmp_neg_fault_no_pending: no pending
cwmp_neg_auth_challenge_outside_acs_cr: acs_cr
cwmp_neg_empty_response_in_acs_cr: empty_ok
cwmp_neg_events_array_too_long: event array
cwmp_neg_acs_response_no_pending: no pending
cwmp_acs_fault_8007: fault code
cwmp_acs_fault_8008: fault code
cwmp_acs_fault_8009: fault code
cwmp_neg_oui_seven_chars: value
cwmp_neg_url_userinfo: value
cwmp_pres_kill_neg: no longer accepts a top-level cwmp sub-config
cwmp_v9_unknown_field_neg: unknown field
```

## 3. 覆盖反查

| 行为面 | 当前用例证据 |
|---|---|
| Inform、事件码、首事务与收尾 | `cwmp_inform_ipv4_2p`、事件/参数边界族、`cwmp_inform_8002_terminate` |
| RPC 请求响应与同连接多事务 | `cwmp_get_param_names_values`、`cwmp_set_parameter_values_single`、`cwmp_http_keepalive_multi_transaction` |
| Fault 与重发 | `cwmp_soap_fault_acs`、逐值 Fault 族、`cwmp_fault_8005_resend_inform` |
| Digest、Connection Request、HTTP 线格式 | `cwmp_connection_request_auth_challenge`、`cwmp_digest_qop_auth_known_vector`、`cwmp_cr_401_no_authorized`、对应负例族 |
| 多会话/并发/IPv6 | `cwmp_multi_session_*`、`cwmp_3_session_*`、`cwmp_concurrent_*`、`cwmp_inform_ipv6` |
| Download/Upload 与流关联 | `cwmp_download_flow_correlation`、`cwmp_upload`、CommandKey/TransferComplete 族 |
| 字段边界与值域 | Event 64、参数名 256、Manufacturer 64、CommandKey 32、OUI、FileSize、FileType、FaultCode 用例 |
| 空配置与未知字段拒绝 | `cwmp_empty_layer_baseline`、`cwmp_pres_kill_neg`、`cwmp_v9_unknown_field_neg` |

## 4. 断言与未覆盖边界

正例至少断言 `packet_count`、`has_handshake`、`terminates` 或 `has_payload`；有稳定 wire 锚点的用例再断言 HTTP 字段或 frames。动态 ID、时间、Cookie、CommandKey 只断言 presence、same_as 或 distinct。负例严格使用 `expect_error`/`error_contains`。

`ChangeDUState`、QueuedTransfers、HTTPS 解密、厂商扩展自动生成和真实商业设备互操作不是当前实现覆盖。真实 pcap/NIC 全量、吞吐、内存、背压和长时运行属于 P5 验收，未运行不宣称已通过。`cwmp_change_du_state_vc` 的实际测试点是 VALUE CHANGE Inform，不是 DU RPC。

## 5. 机器对账命令

```bash
python3 - <<'PY'
import json
cases=json.load(open('trafficgen/test/protocol_pcap/cases/cwmp.json'))
neg=[c for c in cases if c['expect'].get('expect_error')]
assert len(cases)==153 and len(neg)==43
assert all(set(c['spec_json'])=={'layers'} or c['id']=='cwmp_pres_kill_neg' for c in cases)
assert sum(set(c['spec_json']) != {'layers'} for c in cases)==1
assert next(c for c in cases if c['id']=='cwmp_pres_kill_neg')['expect']['expect_error']
assert all(set(c['expect'])=={'expect_error','error_contains'} for c in neg)
print(len(cases), len(cases)-len(neg), len(neg))
PY
```

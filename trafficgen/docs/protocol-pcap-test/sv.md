# sv Pcap Test Results

Cases: 30 — pass 30, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sv_4i4v | 9-2LE full dataset 4 current + 4 voltage: seqData 64 bytes, per-channel instMag 30..135, quality good; also serves as the no-IP proof (eth:sv, no ip layer) | pass | 1 | [pcap](sv/sv_4i4v.pcap) |
| sv_combo_rate_dataset | combo B: dat_set present (tag 0x81 first pin) + smp_rate + mixed int32q/float32 channels | pass | 1 | [pcap](sv/sv_combo_rate_dataset.pcap) |
| sv_combo_vlan_double | combo A: VLAN(200,pri5) + double_send shared-smpCnt + 4i4v quality layout, count=4 | pass | 4 | [pcap](sv/sv_combo_vlan_double.pcap) |
| sv_custom_dataset | non-9-2LE custom dataset: 2 channels (int32 + float32), no per-channel quality, smpRate field omitted (optional-field behavior), smpSynch 2 | pass | 1 | [pcap](sv/sv_custom_dataset.pcap) |
| sv_double_send | redundant double-send: same smpCnt appears twice (2 frames identical bytes), then stream continues; count 6 -> smpCnt 0,0,1,1,2,2 | pass | 6 | [pcap](sv/sv_double_send.pcap) |
| sv_float32 | float32 channel: inst_mag 1.5 -> IEEE754 bytes 3f c0 00 00 | pass | 1 | [pcap](sv/sv_float32.pcap) |
| sv_int32_neg | int32 negative channel: inst_mag -1 -> seqData bytes ff ff ff ff (sign preserved) | pass | 1 | [pcap](sv/sv_int32_neg.pcap) |
| sv_mac_dyn_inc | MAC dynamic inc multi-flow + wrap: flows=3 over range-of-2, flow3 wraps to :01 | pass | 3 | [pcap](sv/sv_mac_dyn_inc.pcap) |
| sv_mac_dyn_list | MAC dynamic list rotation: flows=2 over 2-MAC list | pass | 2 | [pcap](sv/sv_mac_dyn_list.pcap) |
| sv_mac_dyn_rand | MAC dynamic rand (seed=7): flows=2 distinct, seed-reproducible (pins from pcap) | pass | 2 | [pcap](sv/sv_mac_dyn_rand.pcap) |
| sv_neg_appid | negative: appid 0x3999 falls in the GOOSE-reserved range (0x0000-0x3FFF) and must fail; SV segment is 0x4000-0x7FFF | pass | 0 | [pcap]() |
| sv_neg_confrev | negative: conf_rev=0 (must be >= 1, 0 means undefined config version) must fail the task | pass | 0 | [pcap]() |
| sv_neg_ip_carrier | V7b: [ip,sv] chain rejected - sv must not have an ip/transport carrier | pass | 0 | [pcap]() |
| sv_neg_no_data | data missing rejected (validator branch) | pass | 0 | [pcap]() |
| sv_neg_smp_synch | negative: smp_synch=5 (legal set is {0,1,2}) must fail the task | pass | 0 | [pcap]() |
| sv_neg_svid_255 | svID 256 bytes rejected (validator branch: required and <=255) | pass | 0 | [pcap]() |
| sv_neg_type | unsupported data type int64 rejected (only int32/float32) | pass | 0 | [pcap]() |
| sv_neg_vlan | V9 vlan_id upper bound: 4096 rejected at create time | pass | 0 | [pcap]() |
| sv_neg_wrap | negative: samples_per_cycle=0 (illegal wrap/cycle count <1) must fail the task | pass | 0 | [pcap]() |
| sv_neg_zero_appid | explicit appid 0: V9 u==0 pass-through -> validator dual-bound rejects (sv.go:26) | pass | 0 | [pcap]() |
| sv_period | sampling period stability: period_us 250, 100 frames delivered (redundancy of the period-driven sender); timing asserted via time_delta sampling | pass | 100 | [pcap](sv/sv_period.pcap) |
| sv_smp_seq | 9-2LE base sampled-value stream: 3 frames, smpCnt 0/1/2 incrementing, appid 0x4000, length 0x6A(=106), confRev 1, no VLAN, no IP (eth:sv) | pass | 3 | [pcap](sv/sv_smp_seq.pcap) |
| sv_smp_synch_0 | smpSynch value 0 (not synchronized) + appid upper edge 0x7fff accepted | pass | 1 | [pcap](sv/sv_smp_synch_0.pcap) |
| sv_smp_synch_1 | smpSynch value 1 (global) accepted | pass | 1 | [pcap](sv/sv_smp_synch_1.pcap) |
| sv_smp_synch_global | smpSynch field stable at 2 (global/PTP sync) across all frames of the stream | pass | 4 | [pcap](sv/sv_smp_synch_global.pcap) |
| sv_smp_wrap | smpCnt wrap-around: samples_per_cycle=4 -> smpCnt 0,1,2,3,0,1 (wrap at 3->0, never 4); 6 frames | pass | 6 | [pcap](sv/sv_smp_wrap.pcap) |
| sv_vlan | 802.1Q VLAN on SV: vlan_id 100, priority 4 -> TCI 0x8064 inserted before EtherType 0x88ba | pass | 1 | [pcap](sv/sv_vlan.pcap) |
| sv_vn_empty_layer | empty sv layer translates to zero config -> appid 0x0000 lower-bound first hit (sv.go:26) | pass | 0 | [pcap]() |
| sv_vn_presence | D-SV-1 presence: top-level sv sub-config rejected (empty map also dies) | pass | 0 | [pcap]() |
| sv_vn_static_copy | 12.9 static copy: eth layer explicit scalar src_mac + flows=2 rejected | pass | 0 | [pcap]() |

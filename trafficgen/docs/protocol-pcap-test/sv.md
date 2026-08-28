# sv Pcap Test Results

Cases: 12 — pass 12, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sv_4i4v | 9-2LE full dataset 4 current + 4 voltage: seqData 64 bytes, per-channel instMag 30..135, quality good; also serves as the no-IP proof (eth:sv, no ip layer) | pass | 1 | [pcap](sv/sv_4i4v.pcap) |
| sv_custom_dataset | non-9-2LE custom dataset: 2 channels (int32 + float32), no per-channel quality, smpRate field omitted (optional-field behavior), smpSynch 2 | pass | 1 | [pcap](sv/sv_custom_dataset.pcap) |
| sv_double_send | redundant double-send: same smpCnt appears twice (2 frames identical bytes), then stream continues; count 6 -> smpCnt 0,0,1,1,2,2 | pass | 6 | [pcap](sv/sv_double_send.pcap) |
| sv_neg_appid | negative: appid 0x3999 falls in the GOOSE-reserved range (0x0000-0x3FFF) and must fail; SV segment is 0x4000-0x7FFF | pass | 0 | [pcap]() |
| sv_neg_confrev | negative: conf_rev=0 (must be >= 1, 0 means undefined config version) must fail the task | pass | 0 | [pcap]() |
| sv_neg_smp_synch | negative: smp_synch=5 (legal set is {0,1,2}) must fail the task | pass | 0 | [pcap]() |
| sv_neg_wrap | negative: samples_per_cycle=0 (illegal wrap/cycle count <1) must fail the task | pass | 0 | [pcap]() |
| sv_period | sampling period stability: period_us 250, 100 frames delivered (redundancy of the period-driven sender); timing asserted via time_delta sampling | pass | 100 | [pcap](sv/sv_period.pcap) |
| sv_smp_seq | 9-2LE base sampled-value stream: 3 frames, smpCnt 0/1/2 incrementing, appid 0x4000, length 0x6A(=106), confRev 1, no VLAN, no IP (eth:sv) | pass | 3 | [pcap](sv/sv_smp_seq.pcap) |
| sv_smp_synch_global | smpSynch field stable at 2 (global/PTP sync) across all frames of the stream | pass | 4 | [pcap](sv/sv_smp_synch_global.pcap) |
| sv_smp_wrap | smpCnt wrap-around: samples_per_cycle=4 -> smpCnt 0,1,2,3,0,1 (wrap at 3->0, never 4); 6 frames | pass | 6 | [pcap](sv/sv_smp_wrap.pcap) |
| sv_vlan | 802.1Q VLAN on SV: vlan_id 100, priority 4 -> TCI 0x8064 inserted before EtherType 0x88ba | pass | 1 | [pcap](sv/sv_vlan.pcap) |

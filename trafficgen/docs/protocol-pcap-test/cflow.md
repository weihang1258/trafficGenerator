# cflow Pcap Test Results

Cases: 22 — pass 22, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| cflow_boundary_lengths | Minimal legal export length and UDP-only checksum boundary | pass | 1 | [pcap](cflow/cflow_boundary_lengths.pcap) |
| cflow_ipfix_enterprise_ie | IPFIX enterprise IE with PEN | pass | 1 | [pcap](cflow/cflow_ipfix_enterprise_ie.pcap) |
| cflow_ipfix_ipv6_record | IPFIX IPv6 address record | pass | 1 | [pcap](cflow/cflow_ipfix_ipv6_record.pcap) |
| cflow_ipfix_multi_exporter | IPFIX exporters remain distinct by observation domain | pass | 2 | [pcap](cflow/cflow_ipfix_multi_exporter.pcap) |
| cflow_ipfix_observation_domain_sequence | IPFIX observation domain and sequence | pass | 1 | [pcap](cflow/cflow_ipfix_observation_domain_sequence.pcap) |
| cflow_ipfix_template_data_ipv4 | IPFIX template and IPv4 data record | pass | 1 | [pcap](cflow/cflow_ipfix_template_data_ipv4.pcap) |
| cflow_ipfix_timeout_options_template | IPFIX Options Template with timeout fields | pass | 1 | [pcap](cflow/cflow_ipfix_timeout_options_template.pcap) |
| cflow_ipfix_variable_length_ie | IPFIX variable-length enterprise IE boundary | pass | 1 | [pcap](cflow/cflow_ipfix_variable_length_ie.pcap) |
| cflow_neg_address_family | IPv4 template filled by IPv6 record | pass | 0 | [pcap]() |
| cflow_neg_checksum | request nonexistent cflow application checksum | pass | 0 | [pcap]() |
| cflow_neg_field_count | template field count differs from descriptors | pass | 0 | [pcap]() |
| cflow_neg_length | declared message or set length outside body | pass | 0 | [pcap]() |
| cflow_neg_template | data set without template | pass | 0 | [pcap]() |
| cflow_neg_udp_port | profile uses wrong UDP port | pass | 0 | [pcap]() |
| cflow_neg_version | profile version mismatch | pass | 0 | [pcap]() |
| cflow_v9_header_sequence_source | NetFlow v9 header sequence and source identity | pass | 1 | [pcap](cflow/cflow_v9_header_sequence_source.pcap) |
| cflow_v9_ipv6_record | NetFlow v9 IPv6 address record | pass | 1 | [pcap](cflow/cflow_v9_ipv6_record.pcap) |
| cflow_v9_multi_exporter | NetFlow v9 exporters remain distinct | pass | 2 | [pcap](cflow/cflow_v9_multi_exporter.pcap) |
| cflow_v9_multi_record | NetFlow v9 two data records and count | pass | 1 | [pcap](cflow/cflow_v9_multi_record.pcap) |
| cflow_v9_multi_session | NetFlow v9 session template isolation | pass | 2 | [pcap](cflow/cflow_v9_multi_session.pcap) |
| cflow_v9_template_data_ipv4 | NetFlow v9 template and IPv4 data record | pass | 1 | [pcap](cflow/cflow_v9_template_data_ipv4.pcap) |
| cflow_v9_timeout_sampling | NetFlow v9 timeout and sampling metadata | pass | 1 | [pcap](cflow/cflow_v9_timeout_sampling.pcap) |

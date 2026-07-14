package pcapparser

// Reparse re-runs the parser on an existing pcap asset to rebuild derived data
// after a parser-logic upgrade (§15/§17.12). It re-aggregates FlowModel,
// re-reassembles .payloads, and rebuilds the trigram index.
//
// Physical facts that don't change when logic changes are preserved (they're
// re-derived identically from the unchanged pcap file): PacketModel.RawOffset,
// Length, TimestampUs, IndexInFlow, L4Protocol, PayloadHash. Classification
// that may change with logic (Direction, AnomalyFlag, FragGroupID, FragOffset)
// is recomputed.
//
// The caller (asset layer) is responsible for replacing the DB records
// (DeleteAssetFlowsAndPackets + re-insert) and swapping the .payloads/.trigram
// files. Reparse itself just produces a fresh PcapAnalysis with the current
// ParserVersion.
func Reparse(path string, opts *Options) (*PcapAnalysis, error) {
	// Reparse is semantically identical to Parse for v1: the pcap file is the
	// source of truth and Parse recomputes all derived state from it. The
	// distinction is operational (the asset layer swaps files + DB rows and
	// sets Status=reindexing). ParserVersion is stamped by Parse itself.
	return Parse(path, opts)
}

// NeedsReparse reports whether a flow's ParserVersion predates the current
// engine version (§17.12 version consistency). The asset layer uses this to
// prompt a reparse for stale indexes.
func NeedsReparse(storedVersion string) bool {
	return storedVersion != ParserVersion
}

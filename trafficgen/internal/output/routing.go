package output

// SplitByDirection splits packets by their direction tag into two groups
// (c2s/client->server and s2c/server->client) for dual-port output (§16.11).
// directions[i] corresponds to pkts[i]. Returns the two groups; the caller
// writes each to its interface writer.
//
// This is a helper (not a Writer subclass) so the existing Writer interface
// (Write([][]byte)) is unchanged -- the OutputWorker calls this and writes to
// two standard Writers.
func SplitByDirection(pkts [][]byte, directions []string) (c2s, s2c [][]byte) {
	for i, p := range pkts {
		if i < len(directions) && directions[i] == "c2s" {
			c2s = append(c2s, p)
		} else {
			s2c = append(s2c, p)
		}
	}
	return c2s, s2c
}

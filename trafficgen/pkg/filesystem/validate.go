package filesystem

import "errors"

// Validate checks the FileSource fields for user-facing input errors.
// Returns nil when valid. The checks are deliberately narrow: they only
// catch values that would otherwise be silently accepted and lead to
// confusing downstream behavior (e.g. truncated bytes, negative lengths,
// or inverted random ranges that produce empty output).
//
// Exactly-one-source-set is NOT enforced here — the plan specifies silent
// precedence (File > Literal > Fill > Random); fail-loud on multiple sources
// would violate that contract. See payloadcache.resolveBytes for the switch.
func (fs *FileSource) Validate() error {
	if fs == nil {
		return nil
	}
	if fs.Fill != nil {
		// Fill.Byte is type byte so the JSON decoder already truncates
		// values >255 silently. We can't recover the original value
		// here; the guard is on Bytes being non-negative (negative
		// would panic make([]byte, n) on 32-bit and produce a confusing
		// huge allocation on 64-bit).
		if fs.Fill.Bytes < 0 {
			return errors.New("filesystem: Fill.Bytes must not be negative")
		}
	}
	if fs.Random != nil {
		if fs.Random.MinBytes < 0 || fs.Random.MaxBytes < 0 {
			return errors.New("filesystem: Random bytes must not be negative")
		}
		if fs.Random.MinBytes > fs.Random.MaxBytes {
			return errors.New("filesystem: Random.MinBytes must be <= MaxBytes")
		}
	}
	return nil
}

package sigma

import (
	"bytes"
	"encoding/base64"
)

// base64 value modifiers (Sigma |base64 and |base64offset).
//
// A SigmaHQ encoded-command rule matches the base64 encoding of a string, not
// the string itself: an attacker passes `-enc <base64>` / `echo <base64> |
// base64 -d`, so the literal appears only in encoded form on the command line.
// pySigma implements this with two value modifiers that transform the rule's
// value(s) at compile time; the trailing comparison modifier (|contains and
// friends) then applies to the ENCODED result. banken mirrors that: the
// transform runs in compileField before the op is chosen, so
// `CommandLine|base64offset|contains: whoami` compiles to a contains over the
// three offset encodings exactly as pySigma expands it.

// b64Mode is which base64 transform a field carries (none for an ordinary
// field).
type b64Mode int

const (
	b64None   b64Mode = iota
	b64Plain          // |base64:       encode the value, match the encoding
	b64Offset         // |base64offset: the three offset-shifted encodings, OR'd
)

// base64Encode is the plain |base64 transform: standard base64 of the UTF-8
// bytes, matching Python's base64.b64encode (standard alphabet, '=' padding).
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// base64OffsetEncodings is the |base64offset transform. A short string S can
// appear at any of three byte alignments inside a longer base64 blob, and its
// encoding differs per alignment; to find S regardless of where it sits, Sigma
// matches all three. This reproduces pySigma's Base64OffsetModifier exactly:
//
//	start_offsets = (0, 2, 3)
//	end_offsets   = (None, -3, -2)
//	for i in 0..2: b64encode(i*" " + val)[start[i] : end[(len(val)+i) % 3]]
//
// The leading start[i] chars (polluted by the i prepended bytes) are dropped,
// and the trailing end chars (polluted by base64 padding, which depends on the
// total length mod 3) are dropped. Reference vector (pySigma's own test):
// "foobar" -> ["Zm9vYmFy", "Zvb2Jhc", "mb29iYX"].
func base64OffsetEncodings(s string) []string {
	startOffsets := [3]int{0, 2, 3}
	// endOffsets mirrors pySigma's (None, -3, -2); 0 here means "to the end"
	// (Python's None slice bound).
	endOffsets := [3]int{0, -3, -2}
	val := []byte(s)
	out := make([]string, 3)
	for i := 0; i < 3; i++ {
		buf := append(bytes.Repeat([]byte{' '}, i), val...)
		enc := base64.StdEncoding.EncodeToString(buf)
		start := startOffsets[i]
		end := len(enc)
		if eo := endOffsets[(len(val)+i)%3]; eo != 0 {
			end += eo // eo is negative: trim from the right
		}
		if start > end { // defensive: never happens for len>=1, keeps the slice valid
			start = end
		}
		out[i] = enc[start:end]
	}
	return out
}

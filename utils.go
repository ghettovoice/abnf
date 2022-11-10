package abnf

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

func hasUpperLetter(s []byte) bool {
	var hasUpper bool
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, rs := utf8.DecodeRune(s[i:])
			i += rs
			hasUpper = hasUpper || unicode.IsUpper(r)
		} else {
			hasUpper = hasUpper || ('A' <= c && c <= 'Z')
			i++
		}
		if hasUpper {
			break
		}
	}
	return hasUpper
}

func toLower(s []byte) []byte {
	if !hasUpperLetter(s) {
		return s
	}
	return bytes.ToLower(s)
}

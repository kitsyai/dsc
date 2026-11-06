// Package prompt shows the native consent (and, where needed, PIN) dialog
// before every signature. A web page cannot click these dialogs.
package prompt

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/kitsyai/dsc/internal/keystore"
)

const Title = "Digital signature request"

// clean makes untrusted text safe and short enough for a dialog: no control
// characters, no newlines, at most max runes.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '‮' || r == '‭' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

// Message is the dialog body. withPIN adds the PIN instruction.
func Message(c keystore.Consent, withPIN bool) string {
	origin := clean(c.Origin, 100)
	if origin == "" {
		origin = "A program on this computer"
	}
	doc := clean(c.Document, 80)
	if doc == "" {
		doc = "a document"
	}
	signer := clean(c.Signer, 80)
	if signer == "" {
		signer = "(no name)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s wants to digitally sign:\n\n    %s\n\nwith the certificate of %s", origin, doc, signer)
	if t := clean(c.Token, 40); t != "" {
		fmt.Fprintf(&b, " (%s)", t)
	}
	b.WriteString(".\n\nOnly continue if you started this signature yourself.")
	if withPIN {
		b.WriteString("\n\nEnter the token PIN to sign:")
	}
	return b.String()
}

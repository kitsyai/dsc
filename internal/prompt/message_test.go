package prompt

import (
	"strings"
	"testing"

	"github.com/kitsyai/dsc/internal/keystore"
)

func TestMessageSanitizes(t *testing.T) {
	msg := Message(keystore.Consent{
		Origin:   "https://prashantsinha.com",
		Document: "contract\n\nAllow? Click Sign‮.pdf" + strings.Repeat("x", 200),
		Signer:   "Asha Verma",
		Token:    "ePass2003",
	}, true)
	if !strings.Contains(msg, "https://prashantsinha.com wants to digitally sign:") || !strings.Contains(msg, "Asha Verma (ePass2003)") {
		t.Fatal(msg)
	}
	if strings.Contains(msg, "‮") || strings.Contains(msg, "contract\n") {
		t.Fatalf("control characters must not reach the dialog: %q", msg)
	}
	if !strings.Contains(msg, "…") || !strings.HasSuffix(msg, "Enter the token PIN to sign:") {
		t.Fatal(msg)
	}
	if m := Message(keystore.Consent{}, false); !strings.HasPrefix(m, "A program on this computer wants") {
		t.Fatal(m)
	}
}

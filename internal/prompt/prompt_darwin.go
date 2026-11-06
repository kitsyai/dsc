//go:build darwin

package prompt

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/kitsyai/dsc/internal/keystore"
)

// Native shows macOS dialogs through osascript. Untrusted text is passed as
// a script argument, never spliced into the script.
type Native struct{}

const confirmScript = `on run argv
display dialog (item 1 of argv) with title (item 2 of argv) buttons {"Cancel", "Sign"} default button "Cancel" cancel button "Cancel" with icon caution
return "ok"
end run`

const pinScript = `on run argv
set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {"Cancel", "Sign"} default button "Sign" cancel button "Cancel" with icon caution
return text returned of r
end run`

func osascript(script string, args ...string) (string, bool, error) {
	out, err := exec.Command("osascript", append([]string{"-e", script, "--"}, args...)...).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "", false, nil // Cancel exits with status 1.
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimRight(string(out), "\r\n"), true, nil
}

func (Native) Confirm(c keystore.Consent) (bool, error) {
	_, ok, err := osascript(confirmScript, Message(c, false), Title)
	return ok, err
}

func (Native) ConfirmWithPIN(c keystore.Consent) (string, bool, error) {
	return osascript(pinScript, Message(c, true), Title)
}

//go:build !windows && !darwin

package prompt

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/kitsyai/dsc/internal/keystore"
)

// Native shows dialogs through zenity (GNOME and most desktops) or kdialog
// (KDE). Arguments are passed directly, never through a shell.
type Native struct{}

func run(name string, args ...string) (string, bool, error) {
	out, err := exec.Command(name, args...).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "", false, nil // Cancel / No exits non-zero.
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimRight(string(out), "\r\n"), true, nil
}

// zenityText escapes Pango markup, which zenity interprets in --text.
func zenityText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func dialogProgram() string {
	for _, name := range []string{"zenity", "kdialog"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

func (Native) Confirm(c keystore.Consent) (bool, error) {
	switch dialogProgram() {
	case "zenity":
		_, ok, err := run("zenity", "--question", "--title", Title, "--text", zenityText(Message(c, false)),
			"--ok-label", "Sign", "--cancel-label", "Cancel", "--default-cancel")
		return ok, err
	case "kdialog":
		_, ok, err := run("kdialog", "--title", Title, "--warningyesno", Message(c, false), "--yes-label", "Sign", "--no-label", "Cancel")
		return ok, err
	}
	return false, keystore.ErrNoDialogProgram
}

func (Native) ConfirmWithPIN(c keystore.Consent) (string, bool, error) {
	switch dialogProgram() {
	case "zenity":
		return run("zenity", "--entry", "--hide-text", "--title", Title, "--text", zenityText(Message(c, true)),
			"--ok-label", "Sign", "--cancel-label", "Cancel")
	case "kdialog":
		return run("kdialog", "--title", Title, "--password", Message(c, true))
	}
	return "", false, keystore.ErrNoDialogProgram
}

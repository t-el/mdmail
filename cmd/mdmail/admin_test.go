package main

import (
	"strings"
	"testing"
)

// Regression: a password supplied on stdin keeps everything except its line
// terminator, so the stored hash matches what the browser later sends.
func TestReadPasswordLine(t *testing.T) {
	for in, want := range map[string]string{
		"Secret-Pass-123\n":        "Secret-Pass-123",
		"Secret-Pass-123\r\n":      "Secret-Pass-123",
		"Secret-Pass-123":          "Secret-Pass-123",
		" spaced pass phrase \n":   " spaced pass phrase ",
		"Péssword-123\nignored\n":  "Péssword-123",
		"tab\tinside-password\r\n": "tab\tinside-password",
	} {
		got, err := readPasswordLine(strings.NewReader(in))
		if err != nil || got != want {
			t.Errorf("readPasswordLine(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "\n", "\r\n"} {
		if _, err := readPasswordLine(strings.NewReader(in)); err == nil {
			t.Errorf("readPasswordLine(%q): want error", in)
		}
	}
}

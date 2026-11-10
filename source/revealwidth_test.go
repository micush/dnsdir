package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The eye beside a password box turns it into type=text. A rule that sizes only input[type=password]
// stops applying then and the box changes size, so every such rule must name the text type too
// (or select by class instead).
func TestPasswordBoxKeepsItsSizeWhenRevealed(t *testing.T) {
	b, err := os.ReadFile("webui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	n := 0
	for _, m := range regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(css, -1) {
		sel, body := m[1], m[2]
		if !strings.Contains(sel, "[type=password]") && !strings.Contains(sel, `[type="password"]`) {
			continue
		}
		n++
		if !regexp.MustCompile(`(^|[;\s])(min-|max-)?width\s*:|(^|[;\s])flex(-basis)?\s*:|(^|[;\s])padding[a-z-]*\s*:|(^|[;\s])font[a-z-]*\s*:`).MatchString(body) {
			continue
		}
		if !strings.Contains(sel, "[type=text]") && !strings.Contains(sel, `[type="text"]`) {
			t.Errorf("this rule sizes a password box but not the same box once the eye shows it as text: %s", strings.TrimSpace(sel))
		}
	}
	if n < 2 {
		t.Fatalf("found only %d rules for password boxes: has the stylesheet changed?", n)
	}
}

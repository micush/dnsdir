package main

import (
	"os"
	"regexp"
	"testing"
	"unicode/utf8"
)

// The text under a form field is one line and no longer than the field (CLAUDE.md, "Field descriptions"); the explanation is in help.js.
func TestFieldHintsAreShort(t *testing.T) {
	b, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:hint|note): "((?:[^"\\]|\\.)*)"`)
	n := 0
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		n++
		if l := utf8.RuneCountInString(m[1]); l > 45 {
			t.Errorf("a field description of %d characters (the limit is 45): %q", l, m[1])
		}
	}
	if n < 10 {
		t.Fatalf("found only %d hints: has the pattern changed?", n)
	}
}

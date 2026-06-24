package deps

import "testing"

func TestFind(t *testing.T) {
	// `sh` is present on every supported platform.
	if _, ok := Find("sh"); !ok {
		t.Error("expected to find sh on PATH")
	}
	// First-match semantics: a bogus name then a real one.
	if p, ok := Find("brewcheck-no-such-binary-xyz", "sh"); !ok || p == "" {
		t.Error("Find should fall through to the first available name")
	}
	if _, ok := Find("brewcheck-no-such-binary-xyz"); ok {
		t.Error("a missing binary must report not-found")
	}
}

func TestHintsPresent(t *testing.T) {
	for _, k := range []string{"semgrep", "clamav", "yara", "capa"} {
		if Hints[k] == "" {
			t.Errorf("missing install hint for %q", k)
		}
	}
}

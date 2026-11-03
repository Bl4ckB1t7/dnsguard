package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileRPZIncludesExactAndWildcardTriggers(t *testing.T) {
	t.Setenv("RPZ_ZONE", "rpz.local")
	content, err := compileRPZ([]RPZRule{{Domain: "baidu.com", Reason: "test"}})
	if err != nil {
		t.Fatalf("compileRPZ returned error: %v", err)
	}
	for _, trigger := range []string{"baidu.com.rpz.local.", "*.baidu.com.rpz.local."} {
		if !strings.Contains(content, trigger+" 60 CNAME rpz-passthru.") {
			t.Fatalf("missing trigger %q in RPZ output:\n%s", trigger, content)
		}
	}
}

func TestRPZRulesEqualIgnoresRuntimeStatus(t *testing.T) {
	current := []RPZRule{{ID: "current", Domain: "example.com", Action: "passthru", Reason: "approved", Status: "published"}}
	published := []RPZRule{{ID: "published", Domain: "example.com", Action: "passthru", Reason: "approved", Status: "draft"}}
	if !rpzRulesEqual(current, published) {
		t.Fatal("equivalent rules with different runtime status should compare equal")
	}
	published[0].Reason = "changed"
	if rpzRulesEqual(current, published) {
		t.Fatal("changed rule reason should require a new publish")
	}
}

func TestRPZHitCountReadsConfiguredBINDLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rpz.log")
	content := "one rpz QNAME NXDOMAIN rewrite\nplain query\ntwo rpz IP DROP rewrite\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPZ_LOG_FILES", path)
	count, ready := rpzHitCount()
	if !ready || count != 2 {
		t.Fatalf("expected 2 RPZ hits from configured log, got count=%d ready=%v", count, ready)
	}
}

func TestRPZHitCountReportsNotConfigured(t *testing.T) {
	t.Setenv("RPZ_LOG_FILES", "")
	count, ready := rpzHitCount()
	if ready || count != 0 {
		t.Fatalf("expected not-configured result, got count=%d ready=%v", count, ready)
	}
}

func TestRPZHitFingerprintDeduplicatesNodesWithinWindow(t *testing.T) {
	lines := []string{
		"03-Nov-2026 15:37:12.073 client @a 127.0.0.1#41169 (hit-test.example): rpz QNAME NXDOMAIN rewrite hit-test.example/A/IN via hit-test.example.rpz.local",
		"03-Nov-2026 15:37:12.101 client @b 127.0.0.1#36679 (hit-test.example): rpz QNAME NXDOMAIN rewrite hit-test.example/A/IN via hit-test.example.rpz.local",
	}
	first, ok := rpzHitFingerprint(lines[0], 2)
	second, ok2 := rpzHitFingerprint(lines[1], 2)
	if !ok || !ok2 || first != second {
		t.Fatalf("expected matching fingerprints, got %q/%q (%v/%v)", first, second, ok, ok2)
	}
}

func TestNextRuleIDIsUnique(t *testing.T) {
	first := nextRuleID()
	second := nextRuleID()
	if first == second || first == "" || second == "" {
		t.Fatalf("rule IDs are not unique: %q and %q", first, second)
	}
}

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func packageTestRequest() rpzPackageRequest {
	return rpzPackageRequest{
		Zone:       "rpz.local",
		GlobalDeny: "global-deny.rpz.local",
		Primary: setupNode{
			Name:    "primary",
			Role:    "primary",
			Address: "127.0.0.10:53",
		},
		Secondaries: []setupNode{
			{Name: "secondary-1", Role: "secondary", Address: "127.0.0.11:53"},
			{Name: "secondary-2", Role: "secondary", Address: "127.0.0.12:53"},
		},
		TSIGKeyPath: "rpz-manager.key",
		TSIGKeyMode: "admin-generate",
	}
}

func TestRPZPackageIsValidatedAndContainsNoSecret(t *testing.T) {
	setupTestEnvironment(t)
	preview, err := buildRPZPackage(packageTestRequest())
	if err != nil {
		t.Fatalf("valid package request failed: %v", err)
	}
	if preview.Zone != "rpz.local." || preview.GlobalDeny != "global-deny.rpz.local." {
		t.Fatalf("zones were not normalized: %+v", preview)
	}
	if len(preview.Files) < 8 {
		t.Fatalf("package is missing required files: %d", len(preview.Files))
	}
	joined := ""
	for _, file := range preview.Files {
		joined += file.Path + "\n" + file.Content
	}
	for _, required := range []string{
		"README.md",
		"config/rpz-primary.conf",
		"config/rpz-secondary.conf",
		"config/tsig.conf",
		"config/response-policy.conf",
		"zones/db.rpz.local",
		"* IN CNAME .",
		"named-checkzone",
		"named-checkconf",
		"refusing to overwrite",
		"tsig-keygen -a hmac-sha256 rpz-manager",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("package is missing %q", required)
		}
	}
	scriptDir := t.TempDir()
	for _, name := range []string{"apply-rpz-config.sh", "verify-rpz-config.sh"} {
		path := filepath.Join(scriptDir, name)
		if err := os.WriteFile(path, []byte(packageFileContent(preview, name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if output, runErr := exec.Command("bash", "-n", path).CombinedOutput(); runErr != nil {
			t.Fatalf("generated %s has invalid shell syntax: %v\n%s", name, runErr, output)
		}
		if _, lookErr := exec.LookPath("shellcheck"); lookErr == nil {
			if output, runErr := exec.Command("shellcheck", "-x", path).CombinedOutput(); runErr != nil {
				t.Fatalf("generated %s failed shellcheck: %v\n%s", name, runErr, output)
			}
		}
	}
	if strings.Contains(joined, "test-secret") || strings.Contains(joined, "secret-value") {
		t.Fatal("package must not contain TSIG secret material")
	}
	responsePolicy := packageFileContent(preview, "config/response-policy.conf")
	if !strings.Contains(responsePolicy, `zone "rpz.local";`) || !strings.Contains(responsePolicy, `// zone "global-deny.rpz.local";`) {
		t.Fatal("Global Deny must remain commented out in the generated response-policy fragment")
	}
	if !strings.Contains(responsePolicy, "qname-wait-recurse no break-dnssec yes") {
		t.Fatal("generated response-policy must explicitly handle DO=1 RPZ rewrites before recursion")
	}
	primaryConfig := packageFileContent(preview, "config/rpz-primary.conf")
	if !strings.Contains(primaryConfig, `allow-transfer { key rpz-manager; };`) ||
		!strings.Contains(primaryConfig, `also-notify { 127.0.0.11 key rpz-manager;`) ||
		!strings.Contains(primaryConfig, `/var/lib/bind/dnsguard-rpz-primary/db.rpz.local`) {
		t.Fatal("Primary config must sign transfers/notifications and use the writable primary data directory")
	}
	secondaryConfig := packageFileContent(preview, "config/rpz-secondary.conf")
	if !strings.Contains(secondaryConfig, `masters { 127.0.0.10 key rpz-manager; };`) ||
		!strings.Contains(secondaryConfig, `/var/cache/bind/dnsguard-rpz-secondary/db.rpz.local`) {
		t.Fatal("Secondary config must use the TSIG-authenticated master and writable transfer directory")
	}
}

func TestRPZPackageZoneFilesPassNamedCheckzone(t *testing.T) {
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		t.Skip("named-checkzone is not installed")
	}
	setupTestEnvironment(t)
	preview, err := buildRPZPackage(packageTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, file := range preview.Files {
		if !strings.HasPrefix(file.Path, "zones/db.") {
			continue
		}
		path := filepath.Join(dir, filepath.Base(file.Path))
		if err := os.WriteFile(path, []byte(file.Content), 0o640); err != nil {
			t.Fatal(err)
		}
		zone := strings.TrimPrefix(file.Path, "zones/db.")
		command := exec.Command("named-checkzone", zone, path)
		if output, runErr := command.CombinedOutput(); runErr != nil {
			t.Fatalf("named-checkzone rejected %s: %v\n%s", zone, runErr, output)
		}
	}
}

func TestRPZPackagePrimaryFragmentPassesNamedCheckconf(t *testing.T) {
	if _, err := exec.LookPath("named-checkconf"); err != nil {
		t.Skip("named-checkconf is not installed")
	}
	setupTestEnvironment(t)
	preview, err := buildRPZPackage(packageTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "primary-data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, file := range preview.Files {
		if !strings.HasPrefix(file.Path, "zones/db.") {
			continue
		}
		name := filepath.Base(file.Path)
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte(file.Content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(root, "rpz-manager.key")
	if err := os.WriteFile(keyPath, []byte("key \"rpz-manager\" { algorithm hmac-sha256; secret \"c2VjcmV0\"; };\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	tsig := strings.ReplaceAll(packageFileContent(preview, "config/tsig.conf"), "/etc/bind/keys/rpz-manager.key", keyPath)
	if err := os.WriteFile(filepath.Join(root, "tsig.conf"), []byte(tsig), 0o640); err != nil {
		t.Fatal(err)
	}
	primary := packageFileContent(preview, "config/rpz-primary.conf")
	primary = strings.ReplaceAll(primary, "/var/lib/bind/dnsguard-rpz-primary", dataDir)
	namedConf := filepath.Join(root, "named.conf")
	content := fmt.Sprintf("options { directory %q; recursion no; listen-on { any; }; listen-on-v6 { none; }; };\ninclude %q;\n%s", root, filepath.Join(root, "tsig.conf"), primary)
	if err := os.WriteFile(namedConf, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("named-checkconf", "-z", namedConf)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("named-checkconf rejected the generated Primary configuration: %v\n%s", runErr, output)
	}
	secondary := packageFileContent(preview, "config/rpz-secondary.conf")
	secondary = strings.ReplaceAll(secondary, "/var/cache/bind/dnsguard-rpz-secondary", filepath.Join(root, "secondary-data"))
	secondaryConf := filepath.Join(root, "secondary.conf")
	secondaryContent := fmt.Sprintf("options { directory %q; recursion no; listen-on { any; }; listen-on-v6 { none; }; };\ninclude %q;\n%s", root, filepath.Join(root, "tsig.conf"), secondary)
	if err := os.WriteFile(secondaryConf, []byte(secondaryContent), 0o640); err != nil {
		t.Fatal(err)
	}
	command = exec.Command("named-checkconf", secondaryConf)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("named-checkconf rejected the generated Secondary configuration: %v\n%s", runErr, output)
	}
}

func TestRPZPackageRejectsUnsafeInputsAndConflicts(t *testing.T) {
	setupTestEnvironment(t)
	cases := []struct {
		name   string
		mutate func(*rpzPackageRequest)
	}{
		{name: "path traversal", mutate: func(request *rpzPackageRequest) { request.TSIGKeyPath = "../secret.key" }},
		{name: "same zones", mutate: func(request *rpzPackageRequest) { request.GlobalDeny = request.Zone }},
		{name: "invalid node address", mutate: func(request *rpzPackageRequest) { request.Primary.Address = "127.0.0.10:53; touch /tmp/pwned" }},
		{name: "missing secondary", mutate: func(request *rpzPackageRequest) { request.Secondaries = nil }},
		{name: "invalid key mode", mutate: func(request *rpzPackageRequest) { request.TSIGKeyMode = "include-secret" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := packageTestRequest()
			test.mutate(&request)
			if _, err := buildRPZPackage(request); err == nil {
				t.Fatal("unsafe package input was accepted")
			}
		})
	}
	for _, host := range []string{"127.0.0.1", "bind-primary", "bind-primary.example"} {
		if !safeBINDHost(host) {
			t.Fatalf("safe BIND host was rejected: %q", host)
		}
	}
	for _, host := range []string{"bind;touch", "bind..example", "-bad.example", "bad-.example"} {
		if safeBINDHost(host) {
			t.Fatalf("unsafe BIND host was accepted: %q", host)
		}
	}
}

func TestRPZPackageApplyIsIdempotentAndRefusesConflicts(t *testing.T) {
	setupTestEnvironment(t)
	preview, err := buildRPZPackage(packageTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	packageDir := filepath.Join(root, "package")
	if err := os.MkdirAll(packageDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, file := range preview.Files {
		path := filepath.Join(packageDir, file.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o640)
		if file.Executable {
			mode = 0o750
		}
		if err := os.WriteFile(path, []byte(file.Content), mode); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"named-checkzone", "named-checkconf"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\nexit 0\n"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	configRoot := filepath.Join(root, "bind")
	if err := os.MkdirAll(configRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configRoot, "named.conf"), []byte("// existing\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	bindUser, bindGroup := os.Getenv("USER"), os.Getenv("USER")
	checkGeneratedOwner := false
	if os.Geteuid() == 0 {
		if _, lookupErr := user.Lookup("bind"); lookupErr == nil {
			bindUser, bindGroup = "bind", "bind"
			checkGeneratedOwner = true
		}
	}
	run := func(args ...string) error {
		command := exec.Command("bash", append([]string{filepath.Join(packageDir, "apply-rpz-config.sh")}, args...)...)
		command.Env = append(os.Environ(),
			"BIND_CONFIG_ROOT="+configRoot,
			"PRIMARY_DATA_DIR="+filepath.Join(root, "primary-data"),
			"SECONDARY_DATA_DIR="+filepath.Join(root, "secondary-data"),
			"BIND_USER="+bindUser,
			"BIND_GROUP="+bindGroup,
		)
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := run("--check", "primary"); err != nil {
		t.Fatalf("pre-apply check failed: %v", err)
	}
	if err := run("--apply", "primary"); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}
	if checkGeneratedOwner {
		bind, lookupErr := user.Lookup("bind")
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		info, statErr := os.Stat(filepath.Join(configRoot, "dnsguard-rpz", "config", "rpz-primary.conf"))
		if statErr != nil {
			t.Fatal(statErr)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || strconv.FormatUint(uint64(stat.Uid), 10) != bind.Uid || info.Mode().Perm() != 0o640 {
			t.Fatalf("generated BIND fragment has unsafe owner or mode: uid=%v mode=%o", stat, info.Mode().Perm())
		}
	}
	if err := run("--apply", "primary"); err != nil {
		t.Fatalf("repeat apply should be idempotent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configRoot, "dnsguard-rpz", "manifest.json"), []byte("conflict\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := run("--apply", "primary"); err == nil {
		t.Fatal("conflicting generated directory must not be overwritten")
	}
	content, readErr := os.ReadFile(filepath.Join(configRoot, "named.conf"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	text := string(content)
	for _, required := range []string{
		"// existing\n",
		"include \"" + filepath.Join(configRoot, "dnsguard-rpz", "config", "tsig.conf") + "\";",
		"include \"" + filepath.Join(configRoot, "dnsguard-rpz", "config", "rpz-primary.conf") + "\";",
		"include \"" + filepath.Join(configRoot, "dnsguard-rpz", "config", "response-policy.conf") + "\";",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("named.conf is missing managed include %q: %s", required, text)
		}
	}
	if strings.Count(text, "response-policy.conf") != 1 {
		t.Fatalf("repeated apply must not duplicate the response-policy include: %s", text)
	}
}

func TestRPZPackageApplyLoadsFinalNamedConfWithRealBINDChecks(t *testing.T) {
	if _, err := exec.LookPath("named-checkconf"); err != nil {
		t.Skip("named-checkconf is not installed")
	}
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		t.Skip("named-checkzone is not installed")
	}
	setupTestEnvironment(t)
	preview, err := buildRPZPackage(packageTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	packageDir := filepath.Join(root, "package")
	if err := os.MkdirAll(packageDir, 0o750); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "keys", "rpz-manager.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key \"rpz-manager\" { algorithm hmac-sha256; secret \"c2VjcmV0\"; };\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	primaryData := filepath.Join(root, "var", "lib", "bind", "dnsguard-rpz-primary")
	secondaryData := filepath.Join(root, "var", "cache", "bind", "dnsguard-rpz-secondary")
	for _, file := range preview.Files {
		path := filepath.Join(packageDir, file.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		content := file.Content
		if strings.HasPrefix(file.Path, "config/") {
			content = strings.ReplaceAll(content, "/etc/bind/keys/rpz-manager.key", keyPath)
			content = strings.ReplaceAll(content, "/var/lib/bind/dnsguard-rpz-primary", primaryData)
			content = strings.ReplaceAll(content, "/var/cache/bind/dnsguard-rpz-secondary", secondaryData)
		}
		mode := os.FileMode(0o640)
		if file.Executable {
			mode = 0o750
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	namedConf := filepath.Join(root, "named.conf")
	if err := os.WriteFile(namedConf, []byte(fmt.Sprintf("options { directory %q; recursion no; listen-on { any; }; listen-on-v6 { none; }; };\n", root)), 0o640); err != nil {
		t.Fatal(err)
	}
	bindUser := os.Getenv("USER")
	bindGroup := bindUser
	if current, lookupErr := user.Current(); lookupErr == nil {
		bindUser = current.Username
		if group, groupErr := user.LookupGroupId(current.Gid); groupErr == nil {
			bindGroup = group.Name
		}
	}
	run := func(args ...string) error {
		command := exec.Command("bash", append([]string{filepath.Join(packageDir, "apply-rpz-config.sh")}, args...)...)
		command.Env = append(os.Environ(),
			"BIND_CONFIG_ROOT="+root,
			"BIND_NAMED_CONF="+namedConf,
			"PRIMARY_DATA_DIR="+primaryData,
			"SECONDARY_DATA_DIR="+secondaryData,
			"BIND_USER="+bindUser,
			"BIND_GROUP="+bindGroup,
		)
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("%w: %s", runErr, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := run("--check", "primary"); err != nil {
		t.Fatalf("real named.conf preflight failed: %v", err)
	}
	if err := run("--apply", "primary"); err != nil {
		t.Fatalf("real named.conf apply failed: %v", err)
	}
	beforeCheck, err := os.ReadFile(namedConf)
	if err != nil {
		t.Fatal(err)
	}
	if err := run("--check", "primary"); err != nil {
		t.Fatalf("real named.conf repeat preflight failed: %v", err)
	}
	afterCheck, err := os.ReadFile(namedConf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeCheck, afterCheck) {
		t.Fatal("--check modified the already-applied named.conf")
	}
	if err := run("--apply", "primary"); err != nil {
		t.Fatalf("real named.conf repeat apply failed: %v", err)
	}
	content, err := os.ReadFile(namedConf)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Count(text, "response-policy.conf") != 1 || strings.Count(text, "rpz-primary.conf") != 1 || strings.Count(text, "tsig.conf") != 1 {
		t.Fatalf("managed named.conf includes were duplicated or missing: %s", text)
	}
	if err := exec.Command("named-checkconf", "-z", namedConf).Run(); err != nil {
		t.Fatalf("final named.conf failed named-checkconf -z: %v\n%s", err, text)
	}
}

func TestRPZPackagePreviewRequiresAuthenticatedAdministrator(t *testing.T) {
	setupTestEnvironment(t)
	request := httptest.NewRequest(http.MethodPost, "/api/setup/rpz-package/preview", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	setupRPZPackage(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("package preview must require an authenticated administrator, got %d", recorder.Code)
	}
}

func packageFileContent(preview rpzPackagePreview, path string) string {
	for _, file := range preview.Files {
		if file.Path == path {
			return file.Content
		}
	}
	return ""
}

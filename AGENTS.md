# Developer & Agent Instructions: sudo-check

Welcome! This repository contains `sudo-check`, a security audit utility for sudoers configuration policies and target hosts written in Go. Below are the key architecture details, rules, and guidelines to help you navigate and modify this codebase safely.

---

## 1. Project Overview & Architecture

`sudo-check` is designed to be a standalone, self-contained binary. It checks parsed sudoers files (represented in the `cvtsudoers` JSON schema) for security weaknesses, dangerous defaults, and GTFObins bypasses.

### Package Structure
- **`cmd/`**: Cobra command specifications.
  - [root.go](cmd/root.go): Common persistent flags (e.g., `--output-dir`, `--formats`, `--gtfobins-path`, `--cvtsudoers-path`).
  - [scan.go](cmd/scan.go): Command to parse and scan JSON policy files or folders.
  - [system.go](cmd/system.go): Command to run autonomously on a live host by calling `cvtsudoers` and checking local versions/permissions.
  - [update_db.go](cmd/update_db.go): Helper command to download fresh GTFObins catalog dumps.
  - [version.go](cmd/version.go): Command to print the build version, commit, and date injected via ldflags.
- **`pkg/gtfobins/`**:
  - [client.go](pkg/gtfobins/client.go): Loads the embedded GTFObins snapshot (`database.json` via `go:embed`) or external file. Performs matching and handles GTFObins alias redirection (e.g. mapping `awk` to `mawk`).
- **`pkg/audit/`**:
  - [auditor.go](pkg/audit/auditor.go): Combines defaults and command audits.
  - [rules_defaults.go](pkg/audit/rules_defaults.go): Audits global defaults (e.g. `secure_path`, `use_pty`, preserved variables in `env_keep` like `LD_PRELOAD`, `visiblepw`).
  - [rules_commands.go](pkg/audit/rules_commands.go): Audits user command lists against GTFObins, dangerous wildcards, and negated commands. Adjusts severity if mitigations like `noexec` are detected.
  - [rules_system.go](pkg/audit/rules_system.go): Audits target system file permissions and compares the local `sudo --version` against CVE version ranges.
- **`pkg/cvtsudoers/`**:
  - [wrapper.go](pkg/cvtsudoers/wrapper.go): Finds and runs `cvtsudoers` with flags `-e -f json`.
- **`pkg/report/`**:
  - [formatter.go](pkg/report/formatter.go): Report coordinator.
  - [text.go](pkg/report/text.go): Plaintext terminal reporter using ANSI colors.
  - [sarif.go](pkg/report/sarif.go): Exporter for Static Analysis Results Interchange Format.
  - [pdf.go](pkg/report/pdf.go): Programmatic PDF builder using `github.com/go-pdf/fpdf`.
  - [html.go](pkg/report/html.go): Premium self-contained HTML report with dark/light modes and client-side filtering.

---

## 2. Development Guidelines

### Language & Compiler version
- Target Go version: **Go 1.26** (specified in [go.mod](go.mod)). Use standard Go formatting (`go fmt`).

### Cross-Compilation & Build Tags
- Target system audits check the owner of `/etc/sudoers` which relies on Unix syscalls.
- To prevent compilation breaks on non-Unix environments (like Windows), system audit helper functions are separated using build tags:
  - [rules_system_unix.go](pkg/audit/rules_system_unix.go): Active logic for Unix-like OSes (`//go:build !windows`).
  - [rules_system_windows.go](pkg/audit/rules_system_windows.go): Non-operational stub for Windows (`//go:build windows`).
- If you modify file ownership checks or low-level file interactions, make sure to update both files or check OS-specific compile targets.

### Compilation
Build the binary locally using:
```powershell
$env:CGO_ENABLED=0; go build -ldflags="-s -w" -trimpath -o sudo-check.exe
```

### Running Tests & CI Checks
To ensure the CI build will pass, agents must run the following checks locally:

1. **Unit Tests**:
   Run all tests and coverage using:
   ```powershell
   go test -v -race -cover ./...
   ```
   *(Note: If running on a Windows system without Cgo/gcc configured, run without `-race`: `go test -v -cover ./...`)*

2. **Static Analysis**:
   Run `go vet` to catch common mistakes:
   ```powershell
   go vet ./...
   ```

3. **Code Formatting**:
   Ensure all files are formatted according to `gofmt`. Run the check to list unformatted files:
   ```powershell
   gofmt -l .
   ```
   To automatically format all files, run:
   ```powershell
   gofmt -w .
   ```

4. **Module Tidiness**:
   Verify that dependencies are tidy:
   ```powershell
   go mod tidy
   git diff --exit-code go.mod go.sum
   ```

**CRITICAL RULE**: Agents MUST run all unit tests and verify they pass after making any changes to the codebase. Ensure all tests pass, `go vet ./...` succeeds, code is properly formatted via `gofmt`, and modules are tidy before proposing any updates or completing the task.



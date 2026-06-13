# Developer & Agent Instructions: sudo-check

Welcome! This repository contains `sudo-check`, a security audit utility for sudoers configuration policies and target hosts written in Go. Below are the key architecture details, rules, and guidelines to help you navigate and modify this codebase safely.

---

## 1. Project Overview & Architecture

`sudo-check` is designed to be a standalone, self-contained binary. It checks parsed sudoers files (represented in the `cvtsudoers` JSON schema) for security weaknesses, dangerous defaults, and GTFObins bypasses.

### Package Structure
- **`cmd/`**: Cobra command specifications.
  - [root.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/cmd/root.go): Common persistent flags (e.g., `--output-dir`, `--formats`, `--gtfobins-path`, `--cvtsudoers-path`).
  - [scan.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/cmd/scan.go): Command to parse and scan JSON policy files or folders.
  - [system.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/cmd/system.go): Command to run autonomously on a live host by calling `cvtsudoers` and checking local versions/permissions.
  - [update_db.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/cmd/update_db.go): Helper command to download fresh GTFObins catalog dumps.
- **`pkg/gtfobins/`**:
  - [client.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/gtfobins/client.go): Loads the embedded GTFObins snapshot (`database.json` via `go:embed`) or external file. Performs matching and handles GTFObins alias redirection (e.g. mapping `awk` to `mawk`).
- **`pkg/audit/`**:
  - [auditor.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/auditor.go): Combines defaults and command audits.
  - [rules_defaults.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/rules_defaults.go): Audits global defaults (e.g. `secure_path`, `use_pty`, preserved variables in `env_keep` like `LD_PRELOAD`, `visiblepw`).
  - [rules_commands.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/rules_commands.go): Audits user command lists against GTFObins, dangerous wildcards, and negated commands. Adjusts severity if mitigations like `noexec` are detected.
  - [rules_system.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/rules_system.go): Audits target system file permissions and compares the local `sudo --version` against CVE version ranges.
- **`pkg/cvtsudoers/`**:
  - [wrapper.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/cvtsudoers/wrapper.go): Finds and runs `cvtsudoers` with flags `-e -f json`.
- **`pkg/report/`**:
  - [formatter.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/report/formatter.go): Report coordinator.
  - [text.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/report/text.go): Plaintext terminal reporter using ANSI colors.
  - [sarif.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/report/sarif.go): Exporter for Static Analysis Results Interchange Format.
  - [pdf.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/report/pdf.go): Programmatic PDF builder using `github.com/go-pdf/fpdf`.
  - [html.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/report/html.go): Premium self-contained HTML report with dark/light modes and client-side filtering.

---

## 2. Development Guidelines

### Language & Compiler version
- Target Go version: **Go 1.26** (specified in [go.mod](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/go.mod)). Use standard Go formatting (`go fmt`).

### Cross-Compilation & Build Tags
- Target system audits check the owner of `/etc/sudoers` which relies on Unix syscalls.
- To prevent compilation breaks on non-Unix environments (like Windows), system audit helper functions are separated using build tags:
  - [rules_system_unix.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/rules_system_unix.go): Active logic for Unix-like OSes (`//go:build !windows`).
  - [rules_system_windows.go](file:///c:/Users/Florian/OneDrive/Documents/Dev/sudo-check/pkg/audit/rules_system_windows.go): Non-operational stub for Windows (`//go:build windows`).
- If you modify file ownership checks or low-level file interactions, make sure to update both files or check OS-specific compile targets.

### Compilation
Build the binary locally using:
```powershell
go build -o sudo-check
```

### Running Tests
Unit tests are written for `pkg/gtfobins` and `pkg/audit`. Run all tests using:
```powershell
go test -v ./...
```
Ensure all tests pass before proposing any functional updates.

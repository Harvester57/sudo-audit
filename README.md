# sudo-check

`sudo-check` is a standalone, statically compiled security auditing utility for **sudoers** configuration policies and target systems written in Go.

It scans sudoers policies for dangerous defaults, security misconfigurations, and executable binaries that are susceptible to privilege escalation using the **GTFObins** catalog.

---

## Features

- **GTFObins Matching**: Identifies binary rules in sudoers matching GTFObins privilege escalation techniques (e.g. spawning a shell, reading/writing files, library loading).
- **Defaults Auditing**: Audits global configurations such as missing `secure_path`, missing `use_pty` (terminal hijacking protection), dangerous variables added to `env_keep` (like `LD_PRELOAD`, `PYTHONPATH`), and enabling `visiblepw` or `pwfeedback`.
- **Allowed Commands Analysis**: Flags use of wildcards/globs in paths, negated rules (easily bypassed), and `ALL` wildcards.
- **System Verification**: Checks the target host's active `sudo` version against CVE ranges (CVE-2019-14287, CVE-2021-3156 "Baron Samedit", and CVE-2023-27320) and validates `/etc/sudoers` file permissions and ownership.
- **Diverse Exporters**:
  - **Text**: Colorized terminal output.
  - **SARIF**: Static Analysis Results Interchange Format JSON for CI/CD integrations.
  - **PDF**: Programmatically formatted grid layout reports.
  - **HTML**: Premium responsive dark/light mode dashboard with client-side interactive search and severity filters.

---

## Installation & Build

### Prerequisites
- [Go 1.26](https://go.dev/) or later.
- The `cvtsudoers` utility installed on the system (usually packaged with `sudo` itself) if running in autonomous system mode.

### Build from Source
Compile the binary statically using standard Go tools:
```bash
git clone https://github.com/Harvester57/sudo-audit.git
cd sudo-audit
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sudo-check
```

---

## CLI Usage

`sudo-check` uses a subcommand structure powered by Cobra:

```
sudo-check [command] [flags]
```

### 1. Scan Pre-Converted JSON policies
Analyze a single JSON policy file or a directory containing multiple JSON policies converted with `cvtsudoers` beforehand:
```bash
./sudo-check scan /path/to/policies/ -o reports/
```

### 2. Autonomous Local System Scan
Audit the local host autonomously by converting `/etc/sudoers` automatically (requires read privileges; run with `sudo` if necessary):
```bash
sudo ./sudo-check system -o reports/
```

### 3. Update the GTFObins Database
Fetch the latest database snapshot dynamically from the online URL `https://gtfobins.org/api.json` and save it locally:
```bash
./sudo-check update-db -p gtfobins.json
```

### 4. Display Version
Print the injected build version, commit hash, and build date:
```bash
./sudo-check version
```

---

## Command Flags

### Global Flags
- `-o, --output-dir <string>`: Directory to save generated reports (default is stdout for plaintext).
- `-f, --formats <string>`: Comma-separated list of report formats (text, sarif, pdf, html) (default: "text,sarif,pdf,html").
- `--gtfobins-path <string>`: Path to a custom `gtfobins.json` database file.
- `--cvtsudoers-path <string>`: Path to a custom `cvtsudoers` binary.

### Scan-Specific Flags
- `--sudoers-file <string>`: Path to target sudoers file (default "/etc/sudoers").

---

## Developer Guide
For codebase architecture details, cross-compilation configurations, and test setup, please refer to [AGENTS.md](AGENTS.md).

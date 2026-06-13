package audit

// Severity represents the severity level of an audit finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security issue identified in the audit.
type Finding struct {
	ID          string   `json:"id"`          // Unique identifier for the finding type (e.g. SUDO-001)
	Title       string   `json:"title"`       // Short summary
	Description string   `json:"description"` // Detailed explanation
	Severity    Severity `json:"severity"`    // CRITICAL, HIGH, etc.
	User        string   `json:"user"`        // Affected user/group (if command spec check)
	Host        string   `json:"host"`        // Affected host (if command spec check)
	Command     string   `json:"command"`     // Command path involved (if command spec check)
	Context     string   `json:"context"`     // Location/file/line information if available
	Remediation string   `json:"remediation"` // How to fix the finding
}

// Member represents a user, host, runas user, runas group, or command member.
// Since cvtsudoers represents members as objects like {"username": "name"} or {"usergroup": "group"} or {"command": "path"},
// we can define a generic structure with all optional fields.
type Member struct {
	Username     string `json:"username,omitempty"`
	Usergroup    string `json:"usergroup,omitempty"`
	NonUnixGroup string `json:"nonunixgroup,omitempty"`
	Netgroup     string `json:"netgroup,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	NetworkAddr  string `json:"networkaddr,omitempty"`
	Command      string `json:"command,omitempty"`
	CommandAlias string `json:"commandalias,omitempty"`
	UserAlias    string `json:"useralias,omitempty"`
	RunasAlias   string `json:"runasalias,omitempty"`
	HostAlias    string `json:"hostalias,omitempty"`
	Negated      bool   `json:"negated,omitempty"`
}

// GetName returns the name value of the member.
func (m Member) GetName() string {
	if m.Username != "" {
		return m.Username
	}
	if m.Usergroup != "" {
		return "%" + m.Usergroup
	}
	if m.NonUnixGroup != "" {
		return "%:" + m.NonUnixGroup
	}
	if m.Netgroup != "" {
		return "+" + m.Netgroup
	}
	if m.Hostname != "" {
		return m.Hostname
	}
	if m.NetworkAddr != "" {
		return m.NetworkAddr
	}
	if m.Command != "" {
		return m.Command
	}
	if m.CommandAlias != "" {
		return m.CommandAlias
	}
	if m.UserAlias != "" {
		return m.UserAlias
	}
	if m.RunasAlias != "" {
		return m.RunasAlias
	}
	if m.HostAlias != "" {
		return m.HostAlias
	}
	return ""
}

// Option represents a generic key-value flag or string default, or list operation.
type Option map[string]any

// CmndSpec contains the configuration of a command execution permission.
type CmndSpec struct {
	RunasUsers  []Member `json:"runasusers,omitempty"`
	RunasGroups []Member `json:"runasgroups,omitempty"`
	Options     []Option `json:"Options,omitempty"`  // Tags like {"authenticate": false} (NOPASSWD)
	Commands    []Member `json:"Commands,omitempty"` // Commands and aliases allowed
}

// UserSpec maps user and host bindings to a list of allowed commands (CmndSpecs).
type UserSpec struct {
	UserList  []Member   `json:"User_List"`
	HostList  []Member   `json:"Host_List"`
	CmndSpecs []CmndSpec `json:"Cmnd_Specs"`
}

// DefaultBinding defines options bounds to specific users, groups, hosts, or commands.
type DefaultBinding struct {
	Binding []Member `json:"Binding,omitempty"`
	Options []Option `json:"Options"`
}

// SudoersPolicy represents the parsed JSON structure of a sudoers policy.
type SudoersPolicy struct {
	Defaults       []DefaultBinding    `json:"Defaults,omitempty"`
	UserAliases    map[string][]Member `json:"User_Aliases,omitempty"`
	RunasAliases   map[string][]Member `json:"Runas_Aliases,omitempty"`
	HostAliases    map[string][]Member `json:"Host_Aliases,omitempty"`
	CommandAliases map[string][]Member `json:"Command_Aliases,omitempty"`
	UserSpecs      []UserSpec          `json:"User_Specs,omitempty"`
}

// AuditResult gathers all findings from a policy audit and system checks.
type AuditResult struct {
	PolicyFindings []Finding `json:"policy_findings"`
	SystemFindings []Finding `json:"system_findings"`
	SudoVersion    string    `json:"sudo_version,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
}

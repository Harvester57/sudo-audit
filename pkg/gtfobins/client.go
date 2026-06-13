package gtfobins

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed database.json
var embeddedDatabase []byte

// ContextDetails stores specific parameters for a context execution (if any).
type ContextDetails struct {
	Code  string `json:"code,omitempty"`
	Shell bool   `json:"shell,omitempty"`
}

// Exploit represents a technique description and how to run it in various contexts.
type Exploit struct {
	Code     string         `json:"code"`
	Comment  string         `json:"comment,omitempty"`
	Contexts map[string]any `json:"contexts"` // e.g., "sudo": null or "sudo": {"code": "..."}
}

// Executable contains the set of functions/exploits mapped to this binary.
type Executable struct {
	Alias     string               `json:"alias,omitempty"`
	Functions map[string][]Exploit `json:"functions,omitempty"`
}

// Database contains all GTFObins executables.
type Database struct {
	Executables map[string]Executable `json:"executables"`
}

// Client is the entry point for querying the GTFObins database.
type Client struct {
	db Database
}

// NewClient initializes a Client with the embedded database.
func NewClient() (*Client, error) {
	var db Database
	if err := json.Unmarshal(embeddedDatabase, &db); err != nil {
		return nil, fmt.Errorf("failed to parse embedded GTFObins database: %w", err)
	}
	return &Client{db: db}, nil
}

// NewClientFromFile initializes a Client using a custom JSON database path.
func NewClientFromFile(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read GTFObins file: %w", err)
	}
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse GTFObins JSON: %w", err)
	}
	return &Client{db: db}, nil
}

// SudoBypass represents a found bypass method for an executable.
type SudoBypass struct {
	Function string // e.g. "shell", "file-read", "file-write"
	Code     string // The payload command
	Comment  string // Exploitation comment
}

// CheckBinary checks if a binary exists in GTFObins and has any sudo bypass techniques.
// Returns a list of bypass methods or nil if not vulnerable.
func (c *Client) CheckBinary(name string) []SudoBypass {
	currName := name
	for depth := 0; depth < 5; depth++ {
		exe, exists := c.db.Executables[currName]
		if !exists {
			return nil
		}

		if exe.Alias != "" {
			currName = exe.Alias
			continue
		}

		var bypasses []SudoBypass
		for funcName, exploits := range exe.Functions {
			for _, exploit := range exploits {
				// Check if "sudo" context exists in contexts
				if val, ok := exploit.Contexts["sudo"]; ok {
					code := exploit.Code
					// If sudo context has specific details (like a custom code block), use it
					if val != nil {
						if m, isMap := val.(map[string]any); isMap {
							if customCode, exists := m["code"].(string); exists && customCode != "" {
								code = customCode
							}
						}
					}
					bypasses = append(bypasses, SudoBypass{
						Function: funcName,
						Code:     code,
						Comment:  exploit.Comment,
					})
				}
			}
		}
		return bypasses
	}

	return nil
}

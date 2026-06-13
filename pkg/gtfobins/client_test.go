package gtfobins

import (
	"testing"
)

func TestClient_CheckBinary(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	// Test a binary that is known to be in GTFObins with sudo bypasses
	bypasses := client.CheckBinary("find")
	if len(bypasses) == 0 {
		t.Errorf("Expected find to have sudo bypasses, got none")
	}

	hasShell := false
	for _, b := range bypasses {
		if b.Function == "shell" {
			hasShell = true
			if b.Code == "" {
				t.Errorf("Expected shell bypass for find to have a code command")
			}
		}
	}
	if !hasShell {
		t.Errorf("Expected find to have a 'shell' function bypass under sudo")
	}

	// Test an invalid binary name
	invalidBypasses := client.CheckBinary("non-existent-binary-xyz")
	if len(invalidBypasses) != 0 {
		t.Errorf("Expected non-existent binary to have no bypasses, got: %v", invalidBypasses)
	}
}

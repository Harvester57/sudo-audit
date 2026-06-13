//go:build windows

package audit

import (
	"fmt"
	"os"
)

func getUnixOwner(info os.FileInfo) (int, int, error) {
	return 0, 0, fmt.Errorf("ownership audit not supported on Windows")
}

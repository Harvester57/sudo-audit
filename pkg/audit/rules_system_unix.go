//go:build !windows

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func getUnixOwner(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("not a unix file info")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

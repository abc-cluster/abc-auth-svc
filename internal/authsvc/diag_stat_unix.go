//go:build linux || darwin

package authsvc

import (
	"os"
	"syscall"
)

// statOwnerUID returns the file owner's uid via the underlying syscall.Stat_t,
// for the /manage/slots/{slot}/diag handler's workbench_home owner check.
func statOwnerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

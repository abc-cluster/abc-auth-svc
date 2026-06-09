//go:build !linux && !darwin

package authsvc

import "os"

func statOwnerUID(_ os.FileInfo) (int, bool) { return 0, false }

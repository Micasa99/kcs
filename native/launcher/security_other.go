//go:build !linux

package main

import (
	"errors"
	"syscall"
)

func setNoNewPrivileges() error {
	return errors.New("rc-native-launcher only supports Linux")
}

func childProcessAttributes(uid, gid uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		Setpgid:    true,
	}
}

func storagePreflight(requiredMiB int) error {
	return errors.New("rc-native-launcher only supports Linux")
}

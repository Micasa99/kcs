//go:build linux

package main

import (
	"errors"
	"fmt"
	"syscall"
)

const (
	prSetNoNewPrivileges = 38
)

func setNoNewPrivileges() error {
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		prSetNoNewPrivileges,
		1,
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS failed: %w", errno)
	}
	return nil
}

func childProcessAttributes(uid, gid uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		Setpgid:    true,
		Pdeathsig:  syscall.SIGKILL,
	}
}

func storagePreflight(requiredMiB int) error {
	required := uint64(requiredMiB+128) * 1024 * 1024
	var root syscall.Statfs_t
	if err := syscall.Statfs("/", &root); err != nil {
		return err
	}
	if root.Bavail*uint64(root.Bsize) < required {
		return errors.New("insufficient ephemeral-storage headroom")
	}
	for _, path := range []string{"/workspace", "/run/rc-control", "/run/rc-user/home", "/run/rc-user/tmp"} {
		var facts syscall.Statfs_t
		if err := syscall.Statfs(path, &facts); err != nil {
			return err
		}
		if facts.Bavail*uint64(facts.Bsize) < 16*1024*1024 {
			return errors.New("insufficient ephemeral-storage headroom")
		}
	}
	return nil
}

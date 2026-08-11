package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type storageLock struct {
	file *os.File
}

func acquireStorageLock(storagePath string) (*storageLock, error) {
	lockPath := filepath.Join(storagePath, ".certgot.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open storage lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, fmt.Errorf("another certgot process is already running")
		}
		return nil, fmt.Errorf("acquire storage lock: %w", err)
	}
	return &storageLock{file: file}, nil
}

func (lock *storageLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

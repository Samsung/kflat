package main

import "github.com/google/syzkaller/prog"

type SyscallPathMap map[string][]string
type Foka map[string]FokaEntry

type FokaEntry struct {
	Read              []string `json:"read"`
	ReadBranch        []string `json:"read_branch"`
	Write             []string `json:"write"`
	WriteBranch       []string `json:"write_branch"`
	Mmap              []string `json:"mmap"`
	MmapBranch        []string `json:"mmap_branch"`
	Ioctl             []string `json:"ioctl"`
	IoctlBranch       []string `json:"ioctl_branch"`
	IoctlCompat       []string `json:"ioctl_c"`
	IoctlCompatBranch []string `json:"ioctl_c_branch"`
	Permissions       string   `json:"perm"`
	Owner             string   `json:"user"`
	Group             string   `json:"group"`
}

func createSyscallToPathMap(syscalls []*prog.Syscall) SyscallPathMap {
	fileDescriptors := make(map[string][]string)

	for _, syscall := range syscalls {
		if syscall.CallName != "openat" {
			continue
		}

		fileDescriptorName := syscall.Ret.Name()
		nodePaths := syscall.Args[1].Type.(*prog.PtrType).Elem.(*prog.BufferType).Values

		// Too generic of a name, we don't want to collide with more sensible stuff
		if fileDescriptorName == "fd" {
			continue
		}

		fileDescriptors[fileDescriptorName] = nodePaths
	}

	syscallToFileDescriptor := make(SyscallPathMap)
	for _, syscall := range syscalls {
		if syscall.CallName != "ioctl" {
			continue
		}

		targetedFileDescriptor := syscall.Args[0].Type.Name()
		if _, ok := fileDescriptors[targetedFileDescriptor]; ok {
			syscallToFileDescriptor[syscall.Name] = fileDescriptors[targetedFileDescriptor]
		}
	}

	return syscallToFileDescriptor
}

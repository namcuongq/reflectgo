package inject

import (
	"encoding/hex"
	"fmt"
	"reflectgo/utils"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Proc struct {
	file   string
	params string

	stdOutPipeRead  syscall.Handle
	stdOutPipeWrite syscall.Handle
	stdErrPipeRead  syscall.Handle
	stdErrPipeWrite syscall.Handle
	// stdInPipeRead   windows.Handle
	// stdInPipeWrite  windows.Handle

	hProcess windows.Handle
	hThread  windows.Handle
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [1]byte
	Reserved3              [2]uintptr
	Ldr                    uintptr
	ProcessParameters      uintptr
	Reserved4              [104]byte
	Reserved5              [52]uintptr
	PostProcessInitRoutine uintptr
	Reserved6              [128]byte
	Reserved7              [1]uintptr
	SessionId              uint32
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type RTL_USER_PROCESS_PARAMETERS struct {
	Reserved1     [16]byte
	Reserved2     [10]uintptr
	ImagePathName UNICODE_STRING
	CommandLine   UNICODE_STRING
}

func New(file, params string) *Proc {
	var p Proc
	p.file = file
	p.params = params
	return &p
}

func (p *Proc) Run() error {
	err := p.inheritHandle()
	if err != nil {
		return err
	}

	err = p.startProcess()
	if err != nil {
		return err
	}

	p.close()
	return nil
}

func (p *Proc) inheritHandle() error {
	var (
		si = new(syscall.StartupInfo)
		pi = new(syscall.ProcessInformation)
	)

	sa := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1, //true
	}

	syscall.CreatePipe(&p.stdOutPipeRead, &p.stdOutPipeWrite, &sa, 0)
	syscall.CreatePipe(&p.stdErrPipeRead, &p.stdErrPipeWrite, &sa, 0)
	// syscall.CreatePipe(&stdWritePipeRead, &stdWritePipeWrite, &sa, 0)

	si.Flags = syscall.STARTF_USESTDHANDLES
	si.StdErr = p.stdErrPipeWrite
	si.StdOutput = p.stdOutPipeWrite
	si.StdInput = p.stdOutPipeRead

	si.Cb = uint32(unsafe.Sizeof(si))
	cmd := p.file + " " + strings.Repeat(" ", len(p.params)+1)
	cmds, err := syscall.UTF16PtrFromString(cmd)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString %s error: %v\n", cmd, err)
	}

	err = syscall.CreateProcess(nil, cmds, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, si, pi)
	if err != nil {
		return fmt.Errorf("CreateProcess error: %v\n", err)
	}

	p.hProcess = windows.Handle(pi.Process)
	p.hThread = windows.Handle(pi.Thread)
	return nil
}

func (p *Proc) startProcess() error {
	var pbi PROCESS_BASIC_INFORMATION
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err := windows.NtQueryInformationProcess(p.hProcess, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, nil)
	if err != nil {
		return fmt.Errorf("NtQueryInformationProcess error: %v\n", err)
	}

	var peb PEB
	s := uintptr(unsafe.Sizeof(peb))
	err = windows.ReadProcessMemory(p.hProcess, pbi.PebBaseAddress, (*byte)(unsafe.Pointer(&peb)), s, nil)
	if err != nil {
		return fmt.Errorf("PEB ReadProcessMemory at %v error: %v\n", unsafe.Pointer(pbi.PebBaseAddress), err)
	}

	var params RTL_USER_PROCESS_PARAMETERS
	err = windows.ReadProcessMemory(p.hProcess, peb.ProcessParameters, (*byte)(unsafe.Pointer(&params)), uintptr(unsafe.Sizeof(params)), nil)
	if err != nil {
		return fmt.Errorf("Params ReadProcessMemory at %v error: %v\n", unsafe.Pointer(peb.ProcessParameters), err)
	}

	// commandLine := make([]uint16, params.CommandLine.Length)
	// err = windows.ReadProcessMemory(p.hProcess, params.CommandLine.Buffer, (*byte)(unsafe.Pointer(&commandLine[0])), uintptr(params.CommandLine.Length), nil)
	// if err != nil {
	// 	panic(err)
	// }

	newCmd := utils.String2Unicode(p.file + " " + p.params)
	sc, err := hex.DecodeString(newCmd)
	if err != nil {
		return fmt.Errorf("DecodeString %s error: %v\n", newCmd, err)
	}
	sc = append(sc, 0x00)

	oldProtect := uint32(0)
	if err = windows.VirtualProtectEx(p.hProcess, uintptr(unsafe.Pointer(params.CommandLine.Buffer)), uintptr(len(sc)), windows.PAGE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtectEx %v error: %v\n", unsafe.Pointer(params.CommandLine.Buffer), err)
	}

	err = windows.WriteProcessMemory(p.hProcess, uintptr(unsafe.Pointer(params.CommandLine.Buffer)), &sc[0], uintptr(len(sc)), nil)
	if err != nil {
		return fmt.Errorf("WriteProcessMemory at %v failed: %v", unsafe.Pointer(params.CommandLine.Buffer), err)
	}

	// if err = windows.VirtualProtectEx(p.hProcess, uintptr(unsafe.Pointer(params.CommandLine.Buffer)), uintptr(len(sc)), oldProtect, nil); err != nil {
	// 	panic(err)
	// }

	_, err = windows.ResumeThread(p.hThread)
	if err != nil {
		fmt.Printf("ResumeThread failed: %v", err)
	}

	return nil
}

func (p *Proc) close() {
	syscall.CloseHandle(p.stdOutPipeWrite)
	syscall.CloseHandle(p.stdErrPipeWrite)
	// syscall.CloseHandle(stdInPipeWrite)

	stdErr := readPipe(windows.Handle(p.stdErrPipeRead))
	stdOut := readPipe(windows.Handle(p.stdOutPipeRead))

	fmt.Printf("%s%s", stdErr, stdOut)

	syscall.CloseHandle(p.stdOutPipeRead)
	syscall.CloseHandle(p.stdErrPipeRead)
	// syscall.CloseHandle(stdInPipeWrite)

	syscall.CloseHandle(syscall.Handle(p.hProcess))
	syscall.CloseHandle(syscall.Handle(p.hThread))

}

func readPipe(pipe windows.Handle) string {
	result := ""
	buf := make([]byte, 1024+1)
	var read uint32 = 0
	err := windows.ReadFile(pipe, buf, &read, nil)
	for err == nil {
		result += string(buf[:read])
		err = windows.ReadFile(pipe, buf, &read, nil)
	}

	return result
}

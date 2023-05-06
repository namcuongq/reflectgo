package api

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// from https://github.com/RIscRIpt/pecoff/blob/a332238caa877efbcfd6b1c358b716b39d481169/datadir_baserels.go#L152
func (r BASE_RELOCATION_ENTRY) Type() int { return int(r.data >> 12) }

func (r BASE_RELOCATION_ENTRY) Offset() uint32 { return uint32(r.data & 0xFFF) }

func VirtualProtect(address uintptr, size int, newProtect uint32) (oldProtect uint32) {
	virtualProtect.Call(address, uintptr(size), uintptr(newProtect), (uintptr)(unsafe.Pointer(&oldProtect)))
	return oldProtect
}

func WriteMemory(destination uintptr, source []byte, size uintptr) {
	rtlCopyMemory.Call(destination, (uintptr)(unsafe.Pointer(&source[0])), size)
}

func VirtualAlloc(address uintptr, size int, allocationType uint64, protect uint64) uintptr {
	addr, _, _ := virtualAlloc.Call(address, uintptr(size), uintptr(allocationType), uintptr(protect))
	return addr
}

func WaitForSingleObject(thread uintptr, milliseconds uint32) error {
	_, _, err := waitForSingleObject.Call(uintptr(windows.Handle(thread)), uintptr(milliseconds))
	return err
}

func CreateThread(startAddress uintptr) uintptr {
	thread, _, _ := createThread.Call(0, 0, startAddress, uintptr(0), 0, 0)
	return thread
}

func ReadProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr) (val uintptr, e error) {
	var numBytesRead uintptr
	data := make([]byte, x64BIT_BYTE)
	r, _, err := procReadProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(x64BIT_BYTE),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}

	val = uintptr(binary.LittleEndian.Uint64(data))
	return
}

func WriteProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr, val uintptr) (e error) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(val))
	var numBytesRead uintptr

	r, _, err := procWriteProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(x64BIT_BYTE),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	return
}

func FindAllDLL(processId uintptr) ([]string, error) {
	var modules []string
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(processId))
	if err != nil {
		return modules, fmt.Errorf("OpenProcess %v error: %v", processId, err)
	}
	defer syscall.CloseHandle(syscall.Handle(p))

	modulesHandles, err := EnumProcessModules(windows.Handle(p), 256)
	if err != nil {
		return modules, fmt.Errorf("EnumProcessModules %v error: %v", processId, err)
	}

	for _, moduleHandle := range modulesHandles {
		if moduleHandle != 0 {
			modulePathUTF16 := make([]uint16, 128)
			err = GetModuleBaseName(p, windows.Handle(moduleHandle), &modulePathUTF16[0], uint32(len(modulePathUTF16)))
			if err != nil {
				return modules, fmt.Errorf("GetModuleBaseName %v error: %v", processId, err)
			}

			modulePath := windows.UTF16ToString(modulePathUTF16)
			modules = append(modules, modulePath)

		}
	}
	return modules, nil
}

func GetModuleBaseName(process windows.Handle, module windows.Handle, baseName *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleBaseNameW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(baseName)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func EnumProcessModules(hProcess windows.Handle, nSize uintptr) (modules []syscall.Handle, err error) {
	modules = make([]syscall.Handle, nSize)
	var sizeNeeded uint32 = 0
	ret, _, _ := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(nSize), uintptr(unsafe.Pointer(&sizeNeeded)), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return modules, nil
}

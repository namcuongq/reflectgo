package pe

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll      = syscall.NewLazyDLL("ntdll.dll")
	rtlCopyMemory = modntdll.NewProc("RtlCopyMemory")

	kernel32               = syscall.MustLoadDLL("kernel32.dll")
	createThread           = kernel32.MustFindProc("CreateThread")
	waitForSingleObject    = kernel32.MustFindProc("WaitForSingleObject")
	virtualAlloc           = kernel32.MustFindProc("VirtualAlloc")
	virtualProtect         = kernel32.MustFindProc("VirtualProtect")
	procReadProcessMemory  = kernel32.MustFindProc("ReadProcessMemory")
	procWriteProcessMemory = kernel32.MustFindProc("WriteProcessMemory")

	kernelbase = syscall.MustLoadDLL("kernelbase.dll")
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_SIZEOF_SHORT_NAME          = 8
	sizeOfUintPtr                    = unsafe.Sizeof(uintptr(0))
	x64BIT_BYTE                      = 8
)

type (
	DWORD uint32
)

type LONG uint32
type WORD uint16
type BYTE uint8
type ULONGLONG uint64

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]BYTE
	Misc                 DWORD
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAdress DWORD
	SizeOfBlock   DWORD
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersionv         WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD
	AddressOfNames        DWORD
	AddressOfNameOrdinals DWORD
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type IMAGE_THUNK_DATA64 struct {
	AddressOfData ULONGLONG
}

type PIMAGE_IMPORT_BY_NAME struct {
	Hint WORD
	Name byte
}

type BASE_RELOCATION_ENTRY struct {
	data uint16
}

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

package api

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_SIZEOF_SHORT_NAME          = 8
	x64BIT_BYTE                      = 8
)

type (
	DWORD     uint32
	LONG      uint32
	WORD      uint16
	BYTE      uint8
	ULONGLONG uint64
)

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

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type ImageSectionHeader struct {
	Name                         [8]byte
	PhysicalAddressOrVirtualSize uint32
	VirtualAddress               uint32
	SizeOfRawData                uint32
	PointerToRawData             uint32
	PointerToRelocations         uint32
	PointerToLinenumbers         uint32
	NumberOfRelocations          uint16
	NumberOfLinenumbers          uint16
	Characteristics              uint32
}

package pe

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflectgo/utils"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/alexmullins/zip"
	"golang.org/x/sys/windows"
)

type PeData struct {
	file   string
	params string

	isDebug        bool
	startAddress   uintptr
	currentProcess windows.Handle
}

func New(file, params string) (pe *PeData) {
	pe = new(PeData)
	pe.file = file
	pe.params = params
	return
}

func (pe *PeData) Debug() {
	pe.isDebug = true
}
func (pe *PeData) Exec() error {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("get current process error: %v\n", err)
	}
	pe.currentProcess = process
	err = pe.loadPe()
	if err != nil {
		return err
	}

	err = pe.fixAgrs()
	if err != nil {
		return err
	}

	pe.log("Exec", pe.file, pe.params)
	return pe.execAsm()
}

func (pe *PeData) loadPe() error {
	var (
		pSourceBytes []byte
		err          error
	)

	ext := filepath.Ext(pe.file)
	if ext == ".zip" {
		pSourceBytes, err = pe.unZipFile(pe.file)
		if err != nil {
			return err
		}
	} else {
		pSourceBytes, err = os.ReadFile(pe.file)
		if err != nil {
			return err
		}
	}

	var pImageHeader IMAGE_DOS_HEADER
	rdrBytes := bytes.NewReader(pSourceBytes)
	err = binary.Read(rdrBytes, binary.LittleEndian, &pImageHeader)
	if err != nil {
		return fmt.Errorf("Parse pImageHeader error: %s\n", err)
	}

	ntHeaderOffset := pImageHeader.E_lfanew

	var pOldNtHeader = new(IMAGE_NT_HEADERS)
	rdrBytes = bytes.NewReader(pSourceBytes[ntHeaderOffset:])
	err = binary.Read(rdrBytes, binary.LittleEndian, pOldNtHeader)
	if err != nil {
		return fmt.Errorf("Parse pOldNtHeader error: %s\n", err)
	}

	oldPeAddress := pOldNtHeader.OptionalHeader.ImageBase
	pImageBase := VirtualAlloc(uintptr(oldPeAddress), int(pOldNtHeader.OptionalHeader.SizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if pImageBase == 0 {
		pImageBase = VirtualAlloc(uintptr(0), int(pOldNtHeader.OptionalHeader.SizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	}
	pOldNtHeader.OptionalHeader.ImageBase = ULONGLONG(pImageBase)
	pe.log("ImageBase at", unsafe.Pointer(pImageBase))

	//write header
	WriteMemory(pImageBase, pSourceBytes, uintptr(pOldNtHeader.OptionalHeader.SizeOfHeaders))

	sectionHeaderOffset := uint16(uintptr(pImageHeader.E_lfanew) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.OptionalHeader))
	var sectionHeader IMAGE_SECTION_HEADER
	const sectionHeaderSize = unsafe.Sizeof(sectionHeader)

	// write all sections
	pe.log("Write Section")
	for i := WORD(0); i != pOldNtHeader.FileHeader.NumberOfSections; i++ {
		rdrBytes = bytes.NewReader(pSourceBytes[sectionHeaderOffset:])
		err = binary.Read(rdrBytes, binary.LittleEndian, &sectionHeader)
		if err != nil {
			return fmt.Errorf("Parse sectionHeader error: %v\n", err)
		}

		var secName []byte
		for _, b := range sectionHeader.Name {
			if b == 0 {
				break
			}
			secName = append(secName, byte(b))
		}
		pe.log("\tSection", string(secName))
		WriteMemory(pImageBase+uintptr(sectionHeader.VirtualAddress), pSourceBytes[sectionHeader.PointerToRawData:], uintptr(sectionHeader.SizeOfRawData))
		sectionHeaderOffset = sectionHeaderOffset + uint16(sectionHeaderSize)
	}

	//fix IAT
	pe.log("Fix Import Table")
	iatSize := uintptr(pOldNtHeader.OptionalHeader.DataDirectory[1].Size)
	for parsedSize := uintptr(0); parsedSize < iatSize; parsedSize += unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{}) {
		importDesc := (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(pImageBase + parsedSize + uintptr(pOldNtHeader.OptionalHeader.DataDirectory[1].VirtualAddress)))
		if importDesc.OriginalFirstThunk == 0 && importDesc.FirstThunk == 0 {
			break
		}

		libName := windows.BytePtrToString((*byte)(unsafe.Pointer(pImageBase + uintptr(importDesc.Name))))
		pe.log("Import", libName)
		libHandler, err := windows.LoadLibrary(libName)
		if err != nil {
			return fmt.Errorf("Load dll %s error: %v\n", err, libName)
		}

		offsetThunk := uintptr(0)
		offsetField := uintptr(0)
		for {
			fieldThunk := (*IMAGE_THUNK_DATA64)(unsafe.Pointer(pImageBase + offsetField + uintptr(importDesc.FirstThunk)))
			orginThunk := (*IMAGE_THUNK_DATA64)(unsafe.Pointer(pImageBase + offsetThunk + uintptr(importDesc.OriginalFirstThunk)))
			if fieldThunk.AddressOfData == 0 {
				break
			}

			proc := uintptr(0)
			funcName := ""

			if orginThunk.AddressOfData>>63 == 1 { //Import by ordinal
				proc = uintptr(unsafe.Pointer(uintptr(orginThunk.AddressOfData)))
				funcName = fmt.Sprintf("%x", orginThunk.AddressOfData)
			} else {
				byName := (*PIMAGE_IMPORT_BY_NAME)(unsafe.Pointer(pImageBase + uintptr(fieldThunk.AddressOfData)))
				funcName = windows.BytePtrToString(&byName.Name)
				proc, err = windows.GetProcAddress(libHandler, funcName)
				if err != nil {
					return fmt.Errorf("GetProcessAddress %s.%s error: %v\n", libName, funcName, err)
				}
			}

			pe.log(fmt.Sprintf("\tFix %s to %v", funcName, proc))
			fieldThunk.AddressOfData = ULONGLONG(proc)
			offsetThunk += unsafe.Sizeof(orginThunk)
			offsetField += unsafe.Sizeof(fieldThunk)
		}
	}

	if pImageBase != uintptr(oldPeAddress) {
		relocTable := &pOldNtHeader.OptionalHeader.DataDirectory[5]
		pe.fixRelocTable(pImageBase, uintptr(oldPeAddress), relocTable)
	}
	pe.startAddress = uintptr(unsafe.Pointer(pImageBase + uintptr(pOldNtHeader.OptionalHeader.AddressOfEntryPoint)))
	return nil
}

func (pe *PeData) fixAgrs() error {
	ex, err := os.Executable()
	if err != nil {
		return fmt.Errorf("unable to get executable: %v\n", err)
	}

	newArgs := `"` + ex + `" ` + pe.params
	pe.log("New args:", newArgs)
	param, err := hex.DecodeString(utils.String2Unicode(newArgs))
	if err != nil {
		return fmt.Errorf("Error decoding shellcode: %s\n", err)
	}

	newAgrsAddr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(param)), windows.MEM_COMMIT|windows.MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("alloc memory error: %v", err)
	}

	pe.log("New args addr:", unsafe.Pointer(newAgrsAddr))
	err = windows.WriteProcessMemory(pe.currentProcess, newAgrsAddr, &param[0], uintptr(len(param)), nil)
	if err != nil {
		return fmt.Errorf("write new agrs value to memory error: %v\n", err)
	}

	// mov rax, newParamAddr
	commandLineWUpdate := []byte{0x48, 0xB8}
	commandLineWUpdate = append(commandLineWUpdate, utils.UintptrToBytes(&newAgrsAddr)...)
	commandLineWUpdate = append(commandLineWUpdate, []byte{0xC3}...)

	for _, cmd := range []string{
		"GetCommandLineW",
		"GetCommandLineA",
	} {
		funcGetCommandLineXAddr, err := kernelbase.FindProc(cmd)
		if err != nil {
			return fmt.Errorf("find %s address error: %v\n", cmd, err)
		}
		pe.log("kernelbase.", cmd, " address", unsafe.Pointer(funcGetCommandLineXAddr.Addr()))

		err = windows.WriteProcessMemory(pe.currentProcess, uintptr(unsafe.Pointer(funcGetCommandLineXAddr.Addr())), &commandLineWUpdate[0], uintptr(len(commandLineWUpdate)), nil)
		if err != nil {
			return fmt.Errorf("patched function kernelbase.%s error: %v\n", cmd, err)
		}

		pe.log("patched function kernelbase.", cmd, commandLineWUpdate)
	}

	var pbi windows.PROCESS_BASIC_INFORMATION
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(pe.currentProcess, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, &pbiLen)
	if err != nil {
		return fmt.Errorf("call QueryInformationProcess error: %v\n", err)
	}

	pe.log("PebBase address:", unsafe.Pointer(pbi.PebBaseAddress))
	pe.log("ProcessParameters address:", unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))
	pe.log("CommandLine address:", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))+uintptr(0x78)))
	pe.log("Buffer commandLine address:", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters.CommandLine.Buffer))))

	return nil
}

func (pe *PeData) fixRelocTable(newAddr uintptr, oldAddr uintptr, relocDir *IMAGE_DATA_DIRECTORY) error {
	pe.log("Fix RelocTable:", newAddr, oldAddr)
	maxSize := relocDir.Size
	relocAddr := relocDir.VirtualAddress
	var reloc = &IMAGE_BASE_RELOCATION{}
	delta := newAddr - oldAddr
	process := uintptr(pe.currentProcess)

	for parsedSize := uintptr(0); parsedSize < uintptr(maxSize); parsedSize += uintptr(reloc.SizeOfBlock) {
		reloc = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(relocAddr) + parsedSize + newAddr))
		if reloc.VirtualAdress == 0 || reloc.SizeOfBlock == 0 {
			break
		}

		entriesNum := int((uintptr(reloc.SizeOfBlock) - unsafe.Sizeof(IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(BASE_RELOCATION_ENTRY{}))
		pageAddr := reloc.VirtualAdress
		entry := (*BASE_RELOCATION_ENTRY)(unsafe.Pointer((uintptr(unsafe.Pointer(reloc)) + unsafe.Sizeof(IMAGE_BASE_RELOCATION{}))))
		for i := 0; i < entriesNum; i++ {
			var relocationAddr = uintptr(pageAddr) + uintptr(newAddr) + uintptr(entry.Offset())
			readAddr, err := ReadProcessMemoryAsAddr(process, relocationAddr)
			if err != nil {
				return fmt.Errorf("read memory as addr error: %v\n", err)
			}
			readAddr += delta

			err = WriteProcessMemoryAsAddr(process, relocationAddr, readAddr)
			if err != nil {
				return fmt.Errorf("write memory as addr error: %v\n", err)
			}

			entry = (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) + unsafe.Sizeof(BASE_RELOCATION_ENTRY{})))
		}
	}
	return nil
}

func (pe *PeData) execAsm() error {
	// syscall.Syscall(pe.startAddress, 0, 0, 0, 0)
	thread := CreateThread(pe.startAddress)
	return WaitForSingleObject(thread, 0xFFFFFFFF)
}

func (pe *PeData) log(message ...interface{}) {
	if pe.isDebug {
		fmt.Printf("%s", time.Now().Format("02-01-2006 15:04:05 - "))
		fmt.Println(message...)
	}
}

func (pe *PeData) unZipFile(f string) ([]byte, error) {
	pe.log("unzip", f)
	zipr, err := zip.OpenReader(f)
	if err != nil {
		return nil, err
	}

	if len(zipr.File) < 1 {
		return nil, fmt.Errorf("zip file is empty")
	}

	z := zipr.File[0]
	if z.IsEncrypted() {
		password, err := getPassword()
		if err != nil {
			return nil, fmt.Errorf("get password error: %v", err)
		}
		z.SetPassword(password)
	}

	rr, err := z.Open()
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(rr)
	if err != nil {
		return nil, err
	}
	defer rr.Close()

	return buf, nil
}

func getPassword() (text string, err error) {
	var modeOn, modeOff uint32
	stdin := syscall.Handle(os.Stdin.Fd())
	err = syscall.GetConsoleMode(stdin, &modeOn)
	if err != nil {
		return
	}
	modeOff = modeOn &^ 0x0004
	fmt.Printf("password:")
	_, _, _ = procSetConsoleMode.Call(uintptr(stdin), uintptr(modeOff))
	_, err = fmt.Scanln(&text)
	if err != nil {
		return
	}
	_, _, _ = procSetConsoleMode.Call(uintptr(stdin), uintptr(modeOn))
	fmt.Println()
	return strings.TrimSpace(text), nil
}

// not use
func runByChangeCommandLineValue() {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		log.Fatalf("unable to get current process: %v", err)
	}

	var pbi windows.PROCESS_BASIC_INFORMATION
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(process, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, &pbiLen)
	if err != nil {
		panic(err)
	}

	payload := "01" + utils.String2Unicode("E:\\abcd111111111111 44466666811119 123")
	sc, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("payload Address", unsafe.Pointer(&sc[0]))
	fmt.Println("PebBaseAddress", unsafe.Pointer(pbi.PebBaseAddress))
	fmt.Println("ProcessParameters address", unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))
	fmt.Println("commandLine Address", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))+uintptr(0x78)))
	fmt.Println("buffer commandLine Address", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters.CommandLine.Buffer))))

	err = windows.WriteProcessMemory(process, uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters.CommandLine.Buffer)), &sc[0], uintptr(len(sc)), nil)
	// err = windows.WriteProcessMemory(process, uintptr(0x78)+uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters)), &sc[0], uintptr(len(sc)), nil)
	if err != nil {
		log.Fatalf("WriteProcessMemory failed: %v", err)
	}
	// s1 := bin2shell()
	// execAsm(s1)

}

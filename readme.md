### Golang PE Loader

#### Execute .exe file from memory !!!

- Read .exe file
- Parse pe file -> IMAGE_DOS_HEADER
- IMAGE_DOS_HEADER.E_lfanew -> IMAGE_NT_HEADERS
- IMAGE_NT_HEADERS.OptionalHeader.ImageBase -> VirtualAlloc
- WriteMemory(IMAGE_NT_HEADERS.OptionalHeader.ImageBase, exe file, IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders) 
- Write All Sections to memory
- Fix Imporrt table
- Fix FixReloc Table
- Set RIP at IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
- syscall

### Usage

Create config.toml with content
```
File   = 'C:\Windows\system32\net.exe'
Params = "localgroup Administrators abcd /delete"
```

And Run `a.exe --config config.toml`
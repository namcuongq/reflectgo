# Golang PE Loader - Protect yourself from AV and EDR

*** Only Support x64 ****

Features:
* Support zip with password
* Support two modes: reflect or process
* Support unHooking dll by AV or EDR (reflect only)

Common use cases:
* Stealth and Stealth
* Protect yourself away from protective measures

## How it works
*** Mode Reflect or Process ****

### [Reflect] Execute .exe file from memory !!!

- Open .exe file
- Read IMAGE_DOS_HEADER
- From IMAGE_DOS_HEADER.E_lfanew get IMAGE_NT_HEADERS
- Try to allocate a memory block of IMAGE_NT_HEADERS.OptionalHeader.ImageBase.SizeOfImage bytes at position IMAGE_NT_HEADERS.OptionalHeader.ImageBase
      + if can't not allocate at position IMAGE_NT_HEADERS.OptionalHeader.ImageBase -> allocate at new localtion then update IMAGE_NT_HEADERS.OptionalHeader.ImageBase = new address
- WriteMemory(IMAGE_NT_HEADERS.OptionalHeader.ImageBase, exe data, IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders) 
- Parse section headers and Write All Sections to memory
- Fix Imporrt table
      + resolved by loading the corresponding libraries
- If the allocated memory block differs from IMAGE_NT_HEADERS.OptionalHeader.ImageBase -> Update RelocTable
- Set RIP at IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
- syscall or createThread

### [Process] Execute as Process !!!

- Create new suspend process with .exe file
- Modify memory Where command line arguments are stored
- Resume process

### [unHooking] Stealth with AV and EDR

- After successful peloader, get all modules dll in ImportTable
- With each module:
      + find the module address in memory(section .text address)
      + Open dll on disk
      + CreateFileMapping
      + MapViewOfFile
      + Overwrite section .text with origin content on disk (VirtualProtect if need)
- Advance(develop):
      + Replace (Open dll on disk + CreateFileMapping + MapViewOfFile) = ReflectPe(as above)
      + Next step overwrite .text as above

## Usage

```
Usage of reflectgo.exe:
  -c string
        path of file config (default "config.toml")
  -m int
        mode for execute: 0 - reflect || 1 - process
  -v    enable debug
```

Create config.toml with content
```
# <pe file> support .exe or .zip with password
C:\Windows\system32\net.exe
# command line argument to .exe
localgroup Administrators user1 /delete
```

And Run `reflectgo.exe -c config.toml`

## Download

[reflectgo.exe](https://github.com/namcuongq/reflectgo/releases)

## TODO

* [ ] Event Log

## Donation
A GitHub star if you like it !!!
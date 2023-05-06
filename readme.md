# Golang PE Loader - Protect us from AV and EDR

*** Only Support x64 ****

Features:
* Support zip with password
* Support two modes: reflect or process
* Support unHook dll by AV or EDR

Common use cases:
* Stealth and Stealth

## How it works
*** Mode Reflect or Process ****

### [Reflect] Execute .exe file from memory !!!

- Read .exe file
- Parse pe file -> IMAGE_DOS_HEADER
- IMAGE_DOS_HEADER.E_lfanew -> IMAGE_NT_HEADERS
- IMAGE_NT_HEADERS.OptionalHeader.ImageBase -> VirtualAlloc
- WriteMemory(IMAGE_NT_HEADERS.OptionalHeader.ImageBase, exe file, IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders) 
- Write All Sections to memory
- Fix Imporrt table
- Fix FixReloc Table
- Set RIP at IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
- syscall or createThread

### [Process] Execute as Process !!!

- Create new suspend process with .exe file
- Modify memory Where command line arguments are stored
- Resume process

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
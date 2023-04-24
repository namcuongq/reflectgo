package utils

import (
	"fmt"
	"unicode/utf8"
	"unsafe"
)

const (
	sizeOfUintPtr = unsafe.Sizeof(uintptr(0))
)

func UintptrToBytes(u *uintptr) []byte {
	return (*[sizeOfUintPtr]byte)(unsafe.Pointer(u))[:]
}

func String2Unicode(str string) (r string) {
	for i := 0; i < len(str); i++ {
		u, _ := utf8.DecodeRuneInString(fmt.Sprintf("%c", str[i]))
		r += fmt.Sprintf("%x00", u)
	}
	return
}

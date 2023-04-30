package utils

import (
	"fmt"
	"unicode/utf8"
	"unsafe"
)

const (
	SIZE_OF_UNIT_PTR = unsafe.Sizeof(uintptr(0))
)

func UintptrToBytes(u *uintptr) []byte {
	return (*[SIZE_OF_UNIT_PTR]byte)(unsafe.Pointer(u))[:]
}

func String2Unicode(str string) (r string) {
	for i := 0; i < len(str); i++ {
		s := fmt.Sprintf("%c", str[i])
		s += ""
		u, _ := utf8.DecodeRuneInString(s)
		r += fmt.Sprintf("%x00", u)
	}
	return
}

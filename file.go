package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

// File header size, including signature.
const fileHdrSize = 24

// FileHeader represents a COFF file header. It is prepended by the PE
// signature: "PE" (Portable Executable).
type FileHeader struct {
	// The architecture of the computer.
	Arch Arch
	// Number of sections.
	NSection uint16
	// Image creation date and time; measured in seconds since the Unix Epoch.
	Created Time
	// File offset of the symbol table, or zero if no symbol table exists.
	SymTblOffset uint32
	// Number of symbols in the symbol table.
	NSymbol uint32
	// Size of the optional header in bytes.
	OptHdrSize uint16
	// A bitfield which specifies the characteristics of the executable.
	Flags Flag
}

// Arch specifies the architecture of the computer.
type Arch uint16

// Machine architectures.
const (
	// Intel 386 and later processors.
	ArchI386 Arch = 0x014C
	// Intel Itanium processor.
	ArchIA64 Arch = 0x0200
	// x64 processor.
	ArchAMD64 Arch = 0x8664
)

// archName is a map from Arch to string description.
var archName = map[Arch]string{
	ArchI386:  "i368",
	ArchIA64:  "IA64",
	ArchAMD64: "AMD64",
}

func (arch Arch) String() string {
	if s, ok := archName[arch]; ok {
		return s
	}
	return fmt.Sprintf("unknown arch: 0x%04X", uint16(arch))
}

// Time represents a time and date; measured in seconds since the Unix Epoch.
type Time uint32

// Time returns the time.Time representation of t.
func (t Time) Time() time.Time {
	return time.Unix(int64(t), 0)
}

func (t Time) String() string {
	return t.Time().String()
}

// Flag is a bitfield which specifies the characteristics of an executable.
type Flag uint16

// Executable characteristics.
const (
	// The file contains no relocation information.
	FlagNoReloc Flag = 1 << iota
	// The file is executable.
	FlagExecutable
	// The file contains no line numbers.
	FlagNoLineNums
	// The file contains no symbol table.
	FlagNoSymTbl
	_ // obsolete.
	// The application can handle addresses larger than 2 GB.
	FlagLargeAddr
	_ // obsolete.
	// The computer supports 32-bit words.
	Flag32bit
	// The file contains no debugging information. It may be present in a
	// separate file.
	FlagNoDebug
	// If the file is on a removeable media, copy it to and run it from the swap.
	FlagUSBCopyToSwap
	// If the file is on the network, copy it to and run it from the swap.
	FlagNetCopyToSwap
	// The file is a system file.
	FlagSystem
	// The file is a dynamic link library (DLL).
	FlagDLL
	// The file should only be run on a uniprocessor computer.
	FlagUniprocessor
)

// flagName is a map from Flag to string description.
var flagName = map[Flag]string{
	FlagNoReloc:       "no reloc",
	FlagExecutable:    "executable",
	FlagNoLineNums:    "no line numbers",
	FlagNoSymTbl:      "no symbol table",
	FlagLargeAddr:     "large addresses",
	Flag32bit:         "32-bit",
	FlagNoDebug:       "no debug",
	FlagUSBCopyToSwap: "USB copy to swap",
	FlagNetCopyToSwap: "NET copy to swap",
	FlagSystem:        "system file",
	FlagDLL:           "DLL",
	FlagUniprocessor:  "uniprocessor",
}

func (flags Flag) String() string {
	var ss []string
	for i := uint(0); i < 16; i++ {
		mask := Flag(1 << i)
		if flags&mask != 0 {
			flags &^= mask
			s, ok := flagName[mask]
			if !ok {
				s = fmt.Sprintf("unknown flag: 0x%04X", uint16(mask))
			}
			ss = append(ss, s)
		}
	}
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, "|")
}

// FileHeader returns the file header of file.
func (file *File) FileHeader() (fileHdr *FileHeader, err error) {
	if file.fileHdr == nil {
		err = file.parseFileHeader()
		if err != nil {
			return nil, err
		}
	}

	return file.fileHdr, nil
}

// parseFileHeader parses the COFF file header of file.
func (file *File) parseFileHeader() error {
	doshdr, err := file.DOSHeader()
	if err != nil {
		return err
	}
	peoff := int64(doshdr.PEHdrOffset)
	sr := io.NewSectionReader(file.r, peoff, fileHdrSize)

	// Verify the PE signature; "PE" (Portable Executable).
	var magic uint32
	err = binary.Read(sr, binary.LittleEndian, &magic)
	if err != nil {
		return fmt.Errorf("pe.File.parseFileHeader: unable to read signature; %v", err)
	}
	const pe = 0x00004550
	if magic != pe {
		return fmt.Errorf("pe.File.parseFileHeader: invalid signature; expected 0x%08X, got 0x%08X", pe, magic)
	}

	// Parse COFF file header.
	file.fileHdr = new(FileHeader)
	err = binary.Read(sr, binary.LittleEndian, file.fileHdr)
	if err != nil {
		return fmt.Errorf("pe.File.parseFileHeader: unable to read file header; %v", err)
	}

	return nil
}

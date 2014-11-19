package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

// Section header size.
const sectHdrSize = 40

// SectHeader represents a section header.
type SectHeader struct {
	// Section name.
	Name [8]byte
	// The total size of the section when loaded into memory. The raw section is
	// zero-padded to fit.
	VirtSize uint32
	// Address of the section, relative to the image base.
	RelAddr uint32
	// The file size of the section.
	Size uint32
	// File offset of the section. This value is zero for sections that only
	// contain uninitialized data.
	Offset uint32
	// File offset to the relocation entries of the section. This value is zero
	// for sections that have no relocations.
	RelocsOffset uint32
	// File offset to the line-number entries of the section. This value is zero
	// for sections that have no COFF line-numbers.
	LineNumsOffset uint32
	// Number of relocation entries for the section.
	NReloc uint16
	// Number of line-number entries for the section.
	NLineNum uint16
	// A bitfield which specifies the characteristics of the section.
	Flags SectFlag
}

// SectFlag is a bitfield which specifies the characteristics of a section.
type SectFlag uint32

const (
	// SectFlagCode indicates that the section contains executable code.
	SectFlagCode SectFlag = 0x00000020
	// SectFlagData indicates that the section contains initialized data.
	SectFlagData SectFlag = 0x00000040
	// SectFlagBSS indicates that the section contains uninitialized data.
	SectFlagBSS SectFlag = 0x00000080
	// SectFlagLinkInfo indicates that the section contains comments or other
	// information. Only valid for object files.
	SectFlagLinkInfo SectFlag = 0x00000200
	// SectFlagLinkRemove indicates that the section will not become part of the
	// image. Only valid for object files.
	SectFlagLinkRemove SectFlag = 0x00000800
	// SectFlagLinkCOMDAT indicates that the section contains COMDAT data. Only
	// valid for object files.
	SectFlagLinkCOMDAT SectFlag = 0x00001000
	// SectFlagDeferSpecExc resets speculative exception handling bits in the TLB
	// entries for this section.
	SectFlagDeferSpecExc SectFlag = 0x00004000
	// SectFlagGPRef indicates that the section contains data referenced through
	// the global pointer.
	SectFlagGPRef SectFlag = 0x00008000
	// SectFlagObjAlign1 aligns data on a 1-byte boundary. Only valid for object
	// files.
	SectFlagObjAlign1 SectFlag = 0x00100000
	// SectFlagObjAlign2 aligns data on a 2-byte boundary. Only valid for object
	// files.
	SectFlagObjAlign2 SectFlag = 0x00200000
	// SectFlagObjAlign4 aligns data on a 4-byte boundary. Only valid for object
	// files.
	SectFlagObjAlign4 SectFlag = 0x00300000
	// SectFlagObjAlign8 aligns data on a 8-byte boundary. Only valid for object
	// files.
	SectFlagObjAlign8 SectFlag = 0x00400000
	// SectFlagObjAlign16 aligns data on a 16-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign16 SectFlag = 0x00500000
	// SectFlagObjAlign32 aligns data on a 32-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign32 SectFlag = 0x00600000
	// SectFlagObjAlign64 aligns data on a 64-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign64 SectFlag = 0x00700000
	// SectFlagObjAlign128 aligns data on a 128-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign128 SectFlag = 0x00800000
	// SectFlagObjAlign256 aligns data on a 256-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign256 SectFlag = 0x00900000
	// SectFlagObjAlign512 aligns data on a 512-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign512 SectFlag = 0x00A00000
	// SectFlagObjAlign1024 aligns data on a 1024-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign1024 SectFlag = 0x00B00000
	// SectFlagObjAlign2048 aligns data on a 2048-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign2048 SectFlag = 0x00C00000
	// SectFlagObjAlign4096 aligns data on a 4096-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign4096 SectFlag = 0x00D00000
	// SectFlagObjAlign8192 aligns data on a 8192-byte boundary. Only valid for
	// object files.
	SectFlagObjAlign8192 SectFlag = 0x00E00000
	// SectFlagRelocsOverflow indicates that there are more relocations than can
	// be represented by the 16-bit value in the section header. If the value of
	// Relocs in the section header is 0xFFFF, the actual relocation count is
	// stored in the RelAddr field of the first relocation.
	SectFlagRelocsOverflow SectFlag = 0x01000000
	// SectFlagMemDiscard indicates that the section memory can be discarded as
	// needed.
	SectFlagMemDiscard SectFlag = 0x02000000
	// SectFlagMemNoCache indicates that the section memory cannot be cached.
	SectFlagMemNoCache SectFlag = 0x04000000
	// SectFlagMemNoPage indicates that the section memory cannot be paged.
	SectFlagMemNoPage SectFlag = 0x08000000
	// SectFlagMemShared indicates that the section memory can be shared.
	SectFlagMemShared SectFlag = 0x10000000
	// SectFlagMemExec indicates that the section memory can be executed.
	SectFlagMemExec SectFlag = 0x20000000
	// SectFlagMemRead indicates that the section memory can be read.
	SectFlagMemRead SectFlag = 0x40000000
	// SectFlagMemWrite indicates that the section memory can be written to.
	SectFlagMemWrite SectFlag = 0x80000000
)

// sectFlagName is a map from SectFlag to string description.
var sectFlagName = map[SectFlag]string{
	SectFlagCode:           "code",
	SectFlagData:           "data",
	SectFlagBSS:            "bss",
	SectFlagLinkInfo:       "link info",
	SectFlagLinkRemove:     "link remove",
	SectFlagLinkCOMDAT:     "link COMDAT",
	SectFlagDeferSpecExc:   "defer speculative exceptions",
	SectFlagGPRef:          "global pointer reference",
	SectFlagRelocsOverflow: "relocs overflow",
	SectFlagMemDiscard:     "mem discard",
	SectFlagMemNoCache:     "mem no cache",
	SectFlagMemNoPage:      "mem no page",
	SectFlagMemShared:      "mem shared",
	SectFlagMemExec:        "mem exec",
	SectFlagMemRead:        "mem read",
	SectFlagMemWrite:       "mem write",
}

func (flags SectFlag) String() string {
	var ss []string
	for i := uint(0); i < 32; i++ {
		// The alignment should be treated as a value, not a bitfield.
		mask := SectFlag(1 << i)
		if mask >= SectFlagObjAlign1 && mask <= SectFlagObjAlign8192 {
			continue
		}

		if flags&mask != 0 {
			flags &^= mask
			s, ok := sectFlagName[mask]
			if !ok {
				s = fmt.Sprintf("unknown flag: 0x%08X", uint32(mask))
			}
			ss = append(ss, s)
		}
	}

	// The alignment should be treated as a value, not a bitfield.
	if flags >= SectFlagObjAlign1 && flags <= SectFlagObjAlign8192 {
		var align int
		switch flags {
		case SectFlagObjAlign1:
			align = 1
		case SectFlagObjAlign2:
			align = 2
		case SectFlagObjAlign4:
			align = 4
		case SectFlagObjAlign8:
			align = 8
		case SectFlagObjAlign16:
			align = 16
		case SectFlagObjAlign32:
			align = 32
		case SectFlagObjAlign64:
			align = 64
		case SectFlagObjAlign128:
			align = 128
		case SectFlagObjAlign256:
			align = 256
		case SectFlagObjAlign512:
			align = 512
		case SectFlagObjAlign1024:
			align = 1024
		case SectFlagObjAlign2048:
			align = 2048
		case SectFlagObjAlign4096:
			align = 4096
		case SectFlagObjAlign8192:
			align = 8192
		}
		var s string
		if align == 0 {
			s = fmt.Sprintf("unknown align flag: 0x%08X", uint32(flags))
		} else {
			s = fmt.Sprintf("align %d", align)
		}
		ss = append(ss, s)
	}

	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, "|")
}

// SectHeaders returns the section headers of file.
func (file *File) SectHeaders() (sectHdrs []*SectHeader, err error) {
	if file.sectHdrs == nil {
		err = file.parseSectHeaders()
		if err != nil {
			return nil, err
		}
	}

	return file.sectHdrs, nil
}

// parseSectHeaders parses the section headers of file.
func (file *File) parseSectHeaders() error {
	// The file header (and optional header) is immediately followed by section
	// headers.
	doshdr, err := file.DOSHeader()
	if err != nil {
		return err
	}
	optoff := int64(doshdr.PEHdrOffset) + fileHdrSize
	fileHdr, err := file.FileHeader()
	if err != nil {
		return err
	}
	sectHdrsOff := optoff + int64(fileHdr.OptHdrSize)
	sectHdrsSize := int64(fileHdr.NSection) * sectHdrSize
	sr := io.NewSectionReader(file.r, sectHdrsOff, sectHdrsSize)

	// Parse section headers.
	file.sectHdrs = make([]*SectHeader, fileHdr.NSection)
	for i := range file.sectHdrs {
		file.sectHdrs[i] = new(SectHeader)
		err = binary.Read(sr, binary.LittleEndian, file.sectHdrs[i])
		if err != nil {
			return fmt.Errorf("pe.File.parseSectHeaders: error reading section header; %v", err)
		}
	}

	return nil
}

// Section returns the contents of the provided section.
func (file *File) Section(sectHdr *SectHeader) (data []byte, err error) {
	sr := io.NewSectionReader(file.r, int64(sectHdr.Offset), int64(sectHdr.Size))
	return ioutil.ReadAll(sr)
}

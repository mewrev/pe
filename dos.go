package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

// DOS header size, including signature.
const dosHdrSize = 64

// A DOSHeader contains information about the executable environment of 16-bit
// DOS binaries. It is prepended by the DOS signature: "MZ" (Mark Zbikowski).
type DOSHeader struct {
	// Size of the last page in bytes. A page is normally 512 bytes, but the last
	// page may contain between 1 and 512 bytes.
	LastPageSize uint16
	// Number of pages in the file.
	NPage uint16
	// Number of entires in the relocation table.
	NReloc uint16
	// Size of header in paragraphs. A paragraph is 16 bytes.
	NHdrPar uint16
	// Minimum extra paragraphs needed.
	MinAlloc uint16
	// Maximum extra paragraphs needed.
	MaxAlloc uint16
	// Initial (relative) SS value.
	SS uint16
	// Initial SP value.
	SP uint16
	// The checksum word contains the one's complement of the summation of all
	// words in the executable file (excluding itself).
	Checksum uint16
	// Initial IP value.
	IP uint16
	// Initial (relative) CS value.
	CS uint16
	// File offset of the relocation table.
	RelocTblOffset uint16
	// Overlay number.
	OverlayNum uint16
	// Reserved.
	Res [4]uint16
	// OEM identifier (for OEMInfo).
	OEMID uint16
	// OEM information; OEMID specific.
	OEMInfo uint16
	// Reserved.
	Res2 [10]uint16
	// File offset of the PE header.
	PEHdrOffset uint32
}

// DOSHeader returns the DOS header of file.
func (file *File) DOSHeader() (doshdr *DOSHeader, err error) {
	if file.doshdr == nil {
		err = file.parseDOSHeader()
		if err != nil {
			return nil, err
		}
	}

	return file.doshdr, nil
}

// parseDOSHeader parses the DOS header of file.
func (file *File) parseDOSHeader() error {
	sr := io.NewSectionReader(file.r, 0, dosHdrSize)

	// Verify the DOS signature; "MZ" (Mark Zbikowski).
	var magic uint16
	err := binary.Read(sr, binary.LittleEndian, &magic)
	if err != nil {
		return fmt.Errorf("pe.File.parseDOSHeader: unable to read signature; %v", err)
	}
	const mz = 0x5A4D
	if magic != mz {
		return fmt.Errorf("pe.File.parseDOSHeader: invalid signature; expected 0x%04X, got 0x%04X", mz, magic)
	}

	// Parse DOS header.
	file.doshdr = new(DOSHeader)
	err = binary.Read(sr, binary.LittleEndian, file.doshdr)
	if err != nil {
		return fmt.Errorf("pe.File.parseDOSHeader: unable to read DOS header; %v", err)
	}

	// Verify that the reserved fields are all zero.
	for i, v := range file.doshdr.Res {
		if v != 0 {
			log.Printf("pe.File.parseDOSHeader: invalid reserved field %d; expected 0, got %v.\n", i, v)
		}
	}
	for i, v := range file.doshdr.Res2 {
		if v != 0 {
			log.Printf("pe.File.parseDOSHeader: invalid reserved field %d; expected 0, got %v.\n", i, v)
		}
	}

	return nil
}

// DOSStub returns the DOS stub of file as a byte slice.
func (file *File) DOSStub() ([]byte, error) {
	doshdr, err := file.DOSHeader()
	if err != nil {
		return nil, err
	}

	// Read DOS stub.
	peoff := doshdr.PEHdrOffset
	stubSize := int64(peoff - dosHdrSize)
	if stubSize <= 0 {
		return nil, nil
	}
	stubOff := int64(dosHdrSize)
	sr := io.NewSectionReader(file.r, stubOff, stubSize)
	dosStub := make([]byte, stubSize)
	_, err = io.ReadFull(sr, dosStub)
	if err != nil {
		return nil, fmt.Errorf("pe.File.DOSStub: error reading DOS stub; %v", err)
	}

	return dosStub, nil
}

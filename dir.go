package pe

// ImageDebugDirectory is a debugging information data directory.
type ImageDebugDirectory struct {
	// Reserved.
	Characteristics uint32
	// The time and date the debugging information was created.
	TimeDateStamp uint32
	// The major version number of the debugging information format.
	MajorVersion uint16
	// The minor version number of the debugging information format.
	MinorVersion uint16
	// The format of the debugging information.
	Type ImageDebugType
	// The size of the debugging information, in bytes. This value does not
	// include the debug directory itself.
	SizeOfData uint32
	// The address of the debugging information when the image is loaded,
	// relative to the image base.
	AddressOfRawData uint32
	// A file pointer to the debugging information.
	PointerToRawData uint32
}

//go:generate stringer -trimprefix ImageDebugType -type ImageDebugType

// ImageDebugType specifies the format of the debugging information pointed to
// by the debug data directory.
type ImageDebugType uint32

// Debugging information formats.
const (
	// Unknown value, ignored by all tools.
	ImageDebugTypeUnknown ImageDebugType = 0
	// COFF debugging information (line numbers, symbol table, and string table).
	// This type of debugging information is also pointed to by fields in the
	// file headers.
	ImageDebugTypeCOFF ImageDebugType = 1
	// CodeView debugging information. The format of the data block is described
	// by the CodeView 4.0 specification.
	ImageDebugTypeCodeView ImageDebugType = 2
	// Frame pointer omission (FPO) information. This information tells the
	// debugger how to interpret nonstandard stack frames, which use the EBP
	// register for a purpose other than as a frame pointer.
	ImageDebugTypeFPO ImageDebugType = 3
	// Miscellaneous information.
	ImageDebugTypeMisc ImageDebugType = 4
	// Exception information.
	ImageDebugTypeException ImageDebugType = 5
	// Fixup information.
	ImageDebugTypeFixup ImageDebugType = 6
	// The mapping from an RVA in image to an RVA in source image.
	ImageDebugTypeOMapToSrc ImageDebugType = 7
	// The mapping from an RVA in source image to an RVA in image.
	ImageDebugTypeOMapFromSrc ImageDebugType = 8
	// Borland debugging information.
	ImageDebugTypeBorland ImageDebugType = 9
	// Reserved.
	ImageDebugTypeReserved10 ImageDebugType = 10
	// Reserved.
	ImageDebugTypeCLSID ImageDebugType = 11
	// PE determinism or reproducibility.
	ImageDebugTypeRepro ImageDebugType = 16
)

// FPODataRaw represents the stack frame layout for a function on an x86
// computer when frame pointer omission (FPO) optimization is used. The
// structure is used to locate the base of the call frame.
//
// ref: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-fpo_data
type FPODataRaw struct {
	// The offset of the first byte of the function code.
	OffsetStart uint32
	// The number of bytes in the function.
	FuncSize uint32
	// The number of local variables / 4.
	NLocals uint32
	// The size of the parameters / 4.
	Params uint16
	// The number of bytes in the function prolog code.
	Prolog uint8
	// Bitfield of data.
	//
	//    // The number of registers saved.
	//    Regs     : 3 bits
	//    // A variable that indicates whether the function uses structured
	//    // exception handling.
	//    HasSEH   : 1 bit
	//    // A variable that indicates whether the EBP register has been
	//    // allocated.
	//    UseBP    : 1 bit
	//    // Reserved for future use.
	//    Reserved : 1 bit
	//    // A variable that indicates the frame type.
	//    Frame    : 2 bits
	Bitfield uint8
}

// FPOData represents the stack frame layout for a function on an x86 computer
// when frame pointer omission (FPO) optimization is used. The structure is used
// to locate the base of the call frame.
type FPOData struct {
	// The offset of the first byte of the function code.
	OffsetStart uint32
	// The number of bytes in the function.
	FuncSize uint32
	// The number of local variables.
	NLocals uint64
	// The size of the parameters, in bytes.
	Params uint32
	// The number of bytes in the function prolog code.
	Prolog uint8
	// The number of registers saved.
	Regs uint8
	// A variable that indicates whether the function uses structured
	// exception handling.
	HasSEH bool
	// A variable that indicates whether the EBP register has been
	// allocated.
	UseBP bool
	// Reserved for future use.
	Reserved uint8
	// A variable that indicates the frame type.
	Frame FrameType
}

//go:generate stringer -linecomment -type FrameType

// FrameType specifies the frame type of a function.
type FrameType uint8

// Frame types.
const (
	// FPO frame
	FrameTypeFPO FrameType = 0 // FPO
	// Non-FPO frame
	FrameTypeNonFPO FrameType = 3 // NonFPO
	// Trap frame
	FrameTypeTrap FrameType = 1 // Trap
	// TSS frame
	FrameTypeTSS FrameType = 2 // TSS
)

// ParseFPOData parses the given raw data structure as an FPO data structure.
func ParseFPOData(raw FPODataRaw) FPOData {
	// TODO: use binary literal
	// Regs     : 3 bits
	regs := uint8(raw.Bitfield & 0x07) // 0b00000111
	// HasSEH   : 1 bit
	hasSEH := (raw.Bitfield & 0x08) != 0 // 0b00001000
	// UseBP    : 1 bit
	useBP := (raw.Bitfield & 0x10) != 0 // 0b00010000
	// Reserved : 1 bit
	reserved := uint8(raw.Bitfield & 0x20 >> 5) // 0b00100000
	// Frame    : 2 bits
	frame := FrameType(raw.Bitfield & 0xC0 >> 6) // 0b11000000
	fpo := FPOData{
		OffsetStart: raw.OffsetStart,
		FuncSize:    raw.FuncSize,
		NLocals:     uint64(raw.NLocals) * 4,
		Params:      uint32(raw.Params) * 4, // compute size in bytes.
		Prolog:      raw.Prolog,
		Regs:        regs,
		HasSEH:      hasSEH,
		UseBP:       useBP,
		Reserved:    reserved,
		Frame:       frame,
	}
	return fpo
}

package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"
)

// Maximum optional header size, which includes 16 data directories.
const maxOptHdrSize = 224

// OptHeader represents an optional header.
type OptHeader struct {
	OptHeader32
	// Data directories contains the location and size of various data
	// structures. The following is a list of data directories as specified by
	// index.
	//
	//     0: Export table.
	//     1: Import table.
	//     2: Resource table.
	//     3: Exception table.
	//     4: Certificate table.
	//     5: Base relocation table.
	//     6: Debugging information.
	//     7: Architecture-specific data.
	//     8: Global pointer register.
	//     9: Thread local storage (TLS) table.
	//    10: Load configuration table.
	//    11: Bound import table.
	//    12: Import address table.
	//    13: Delay import descriptor.
	//    14: CLR header.
	//    15: Reserved.
	DataDirs []DataDirectory
}

// Data directory indices.
const (
	DataDirExportTable           = 0  // Export table.
	DataDirImportTable           = 1  // Import table.
	DataDirResourceTable         = 2  // Resource table.
	DataDirExceptionTable        = 3  // Exception table.
	DataDirCertificateTable      = 4  // Certificate table.
	DataDirBaseRelocationTable   = 5  // Base relocation table.
	DataDirDebug                 = 6  // Debugging information.
	DataDirArchitecture          = 7  // Architecture-specific data.
	DataDirGlobalPtr             = 8  // Global pointer register.
	DataDirTLSTable              = 9  // Thread local storage (TLS) table.
	DataDirLoadConfigTable       = 10 // Load configuration table.
	DataDirBoundImport           = 11 // Bound import table.
	DataDirIAT                   = 12 // Import address table.
	DataDirDelayImportDescriptor = 13 // Delay import descriptor.
	DataDirCLRHeader             = 14 // CLR header.
	DataDirReserved              = 15 // Reserved.
)

// OptHeader32 represents a 32-bit optional header.
type OptHeader32 struct {
	// The state of the image file.
	State OptState
	// Major linker version.
	MajorLinkVer uint8
	// Minor linker version.
	MinorLinkVer uint8
	// Size of the code section in bytes, or the sum of all such sections if
	// there are multiple code sections.
	CodeSize uint32
	// Size of the data section in bytes, or the sum of all such sections if
	// there are multiple data sections.
	DataSize uint32
	// Size of the uninitialized data section in bytes, or the sum of all such
	// sections if there are multiple uninitialized data sections.
	BSSSize uint32
	// Pointer to the entry point function, relative to the image base.
	EntryRelAddr uint32
	// Pointer to the beginning of the code section, relative to the image base.
	CodeBase uint32
	// Pointer to the beginning of the data section, relative to the image base.
	DataBase uint32
	// The base address is the starting-address of a memory-mapped EXE or DLL.
	// The default value for DLLs is 0x10000000 and the default value for
	// applications is 0x00400000.
	ImageBase uint32
	// The virtual address of each section is aligned to a multiple of this
	// value. The default section alignment is the page size of the system.
	SectAlign uint32
	// The file offset of each section is aligned to a multiple of this value.
	// The default file alignment is 512.
	FileAlign uint32
	// Major operating system version.
	MajorOSVer uint16
	// Minor operating system version.
	MinorOSVer uint16
	// Major image version.
	MajorImageVer uint16
	// Minor image version.
	MinorImageVer uint16
	// Major subsystem version.
	MajorSubsystemVer uint16
	// Minor subsystem version.
	MinorSubsystemVer uint16
	// Reserved.
	Res uint32
	// Size of the image, in bytes, including all headers. Must be a multiple of
	// SectAlign.
	ImageSize uint32
	// The combined size of the following items, rounded to a multiple of
	// FileAlign.
	//    * The PEHdrOffset member of the DOSHeader.
	//    * The 4 byte PE-signature.
	//    * The FileHeader.
	//    * The OptHeader.
	//    * All section headers.
	HdrSize uint32
	// The checksum is an additive checksum of the file.
	Checksum uint32
	// The subsystem required to run an image.
	Subsystem Subsystem
	// A bitfield which specifies the DLL characteristics of the image.
	Flags DLLFlag
	// The number of bytes to reserve for the stack.
	ReserveStackSize uint32
	// The size of the stack at load time.
	InitStackSize uint32
	// The number of bytes to reserve for the heap.
	ReserveHeapSize uint32
	// The size of the heap at load time.
	InitHeapSize uint32
	// Obsolete.
	LoaderFlags uint32
	// Number of data directories.
	NDataDir uint32
}

// OptState specifies the state of the image file.
type OptState uint16

const (
	// OptState32 represents a 32-bit executable image.
	OptState32 OptState = 0x010B
	// OptState64 represents a 64-bit executable image.
	OptState64 OptState = 0x020B
	// OptStateROM represents a ROM image.
	OptStateROM OptState = 0x0107
)

// optStateName is a map from OptState to string description.
var optStateName = map[OptState]string{
	OptState32:  "32-bit",
	OptState64:  "64-bit",
	OptStateROM: "ROM",
}

func (state OptState) String() string {
	if s, ok := optStateName[state]; ok {
		return s
	}
	return fmt.Sprintf("unknown state: 0x%04X", uint16(state))
}

// Subsystem specifies the subsystem required to run an image.
type Subsystem uint16

// Subsystems.
const (
	// SubsystemUnknown represents an unknown subsystem.
	SubsystemUnknown Subsystem = iota
	// SubsystemNative represents a device driver or native system process; no
	// subsystem required.
	SubsystemNative
	// SubsystemWinGUI represents a Windows graphical user interface (GUI)
	// subsystem.
	SubsystemWinGUI
	// SubsystemWinCLI represents a Window command line interface (CLI)
	// subsystem.
	SubsystemWinCLI
	_
	// SubsystemOS2CLI represents a OS/2 CLI subsystem.
	SubsystemOS2CLI
	_
	// SubsystemPOSIXCLI represents a POSIX CLI subsystem.
	SubsystemPOSIXCLI
	_
	// SubsystemWinCEGUI represents a Windows CE GUI subsystem.
	SubsystemWinCEGUI
	// SubsystemEFIApp represents an Extensible Firmware Interface (EFI)
	// application.
	SubsystemEFIApp
	// SubsystemEFIBootDriver represents an EFI driver with boot services.
	SubsystemEFIBootDriver
	// SubsystemEFIRuntimeDriver represents an EFI driver with run-time services.
	SubsystemEFIRuntimeDriver
	// SubsystemEFIROM represents an EFI ROM image.
	SubsystemEFIROM
	// SubsystemXbox represents an Xbox system.
	SubsystemXbox
	_
	// SubsystemWinBootApp represents a boot application.
	SubsystemWinBootApp
)

// subsystemName is a map from Subsystem to string description.
var subsystemName = map[Subsystem]string{
	SubsystemUnknown:          "unknown",
	SubsystemNative:           "native",
	SubsystemWinGUI:           "Windows GUI",
	SubsystemWinCLI:           "Windows CLI",
	SubsystemOS2CLI:           "OS/2 CLI",
	SubsystemPOSIXCLI:         "POSIX CLI",
	SubsystemWinCEGUI:         "Windows CE GUI",
	SubsystemEFIApp:           "EFI application",
	SubsystemEFIBootDriver:    "EFI boot driver",
	SubsystemEFIRuntimeDriver: "EFI runtime driver",
	SubsystemEFIROM:           "EFI ROM",
	SubsystemXbox:             "Xbox",
	SubsystemWinBootApp:       "boot application",
}

func (subsystem Subsystem) String() string {
	if s, ok := subsystemName[subsystem]; ok {
		return s
	}
	return fmt.Sprintf("unknown subsystem: 0x%04X", uint16(subsystem))
}

// DLLFlag is a bitfield which specifies the DLL characteristics of an image.
type DLLFlag uint16

// DLL characteristics.
const (
	// DLLFlagDynBase indicates that the DLL can be relocated at load time.
	DLLFlagDynBase DLLFlag = 0x0040
	// DLLFlagForceIntegrity forces code integrity checks.
	DLLFlagForceIntegrity DLLFlag = 0x0080
	// DLLFlagCanDEP indicates that the image is compatible with data execution
	// prevention (DEP).
	DLLFlagCanDEP DLLFlag = 0x0100
	// DLLFlagNoIsolation indicates that the image shouldn't be isolated.
	DLLFlagNoIsolation DLLFlag = 0x0200
	// DLLFlagNoSEH indicates that the image doesn't use structured exception
	// handling (SEH). No handlers can be called in this image.
	DLLFlagNoSEH DLLFlag = 0x0400
	// DLLFlagNoBind specifies that the linker shouldn't bind the image.
	DLLFlagNoBind DLLFlag = 0x0800
	// DLLFlagWDMDriver represents a Windows Driver Model (WDM) driver.
	DLLFlagWDMDriver DLLFlag = 0x2000
	// DLLFlagCanRDS indicates that the image is remove desktop service (RDS)
	// aware.
	DLLFlagCanRDS DLLFlag = 0x8000
)

// dllFlagName is a map from DLLFlag to string description.
var dllFlagName = map[DLLFlag]string{
	DLLFlagDynBase:        "dynamic base",
	DLLFlagForceIntegrity: "force integrity",
	DLLFlagCanDEP:         "can DEP",
	DLLFlagNoIsolation:    "no isolation",
	DLLFlagNoSEH:          "no SEH",
	DLLFlagNoBind:         "no bind",
	DLLFlagWDMDriver:      "WDM driver",
	DLLFlagCanRDS:         "can RDS",
}

func (flags DLLFlag) String() string {
	var ss []string
	for i := uint(0); i < 16; i++ {
		mask := DLLFlag(1 << i)
		if flags&mask != 0 {
			flags &^= mask
			s, ok := dllFlagName[mask]
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

// A DataDirectory contains the location and size of various data structures.
type DataDirectory struct {
	// Relative address of the table.
	RelAddr uint32
	// Size of the table in bytes.
	Size uint32
}

// OptHeader returns the optional header of file.
func (file *File) OptHeader() (opthdr *OptHeader, err error) {
	if file.opthdr == nil {
		err = file.parseOptHeader()
		if err != nil {
			return nil, err
		}
	}

	return file.opthdr, nil
}

// parseOptHeader parses the optional header of file.
func (file *File) parseOptHeader() error {
	doshdr, err := file.DOSHeader()
	if err != nil {
		return err
	}
	optoff := int64(doshdr.PEHdrOffset) + fileHdrSize
	sr := io.NewSectionReader(file.r, optoff, maxOptHdrSize)

	// Parse optional header.
	file.opthdr = new(OptHeader)
	opthdr := file.opthdr
	err = binary.Read(sr, binary.LittleEndian, &opthdr.OptHeader32)
	if err != nil {
		return fmt.Errorf("pe.File.parseOptHeader: unable to read optional header; %v", err)
	}

	// Verify that the reserved field is zero.
	if opthdr.Res != 0 {
		log.Printf("pe.File.parseOptHeader: invalid reserved field; expected 0, got %d.\n", opthdr.Res)
	}

	// Parse data directories.
	// TODO(u): Ignore void/zero data directories (using a for loop).
	opthdr.DataDirs = make([]DataDirectory, opthdr.NDataDir)
	err = binary.Read(sr, binary.LittleEndian, &opthdr.DataDirs)
	if err != nil {
		return fmt.Errorf("pe.File.parseOptHeader: unable to read data directories; %v", err)
	}

	return nil
}

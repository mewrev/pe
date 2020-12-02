// Package pe implements access to the Portable Executable (PE) file format.
//
// ref: http://msdn.microsoft.com/en-us/gg463119.aspx
// ref: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
package pe

import (
	"io"
	"os"
)

// File represents a Portable Executable (PE) file.
type File struct {
	// DOS Header.
	doshdr *DOSHeader
	// COFF file header.
	fileHdr *FileHeader
	// Optional header.
	opthdr *OptHeader
	// Section headers.
	sectHdrs []*SectHeader
	// Overlay.
	overlay []byte
	// Underlying reader.
	r ReadAtSeeker
	io.Closer
}

// Open returns a new File for accessing the PE binary at path.
//
// Note: The Close method of the file must be called when finished using it.
func Open(path string) (file *File, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	file, err = New(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	file.Closer = f
	return file, nil
}

// ReadAtSeeker is the interface that wraps the basic ReadAt and Seek methods.
type ReadAtSeeker interface {
	io.ReaderAt
	io.Seeker
}

// New returns a new File for accessing the PE binary of r.
func New(r ReadAtSeeker) (file *File, err error) {
	// TODO(u): Figure out which headers that should always be parsed.
	//    * DOS header
	//       - Contains no relevant information, but is required to locate the
	//         file header offset.
	//    * File header
	//       - Specifies the intended architecture of the binary, and the number
	//         of sections contained within the file.
	//    * Optional header
	//       - Specifies the code, data and image base addresses, the entry point
	//         point address, and the data directories.
	return &File{r: r}, nil
}

// Parse parses all headers of file.
func (file *File) Parse() error {
	// Parse DOS header.
	err := file.parseDOSHeader()
	if err != nil {
		return err
	}

	// Parse COFF file header.
	err = file.parseFileHeader()
	if err != nil {
		return err
	}

	// Parse optional header.
	if file.fileHdr.OptHdrSize > 0 {
		err = file.parseOptHeader()
		if err != nil {
			return err
		}
	}

	// Parse section headers.
	err = file.parseSectHeaders()
	if err != nil {
		return err
	}

	// Parse sections.

	//// Parse data directories.
	//for _, dataDir := range file.OptHdr.DataDirs {
	//	if dataDir.Size == 0 {
	//		continue
	//	}
	//	// TODO(u): Parse the data directories.
	//}

	return nil
}

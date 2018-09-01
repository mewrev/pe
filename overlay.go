package pe

import (
	"io"

	"github.com/pkg/errors"
)

// Overlay returns the overlay of the PE fil (i.e. any optional bytes directly
// succeeding the image).
func (file *File) Overlay() ([]byte, error) {
	if file.overlay == nil {
		if err := file.parseOverlay(); err != nil {
			return nil, err
		}
	}
	return file.overlay, nil
}

// parseOverlay parses the overlay of the PE file.
func (file *File) parseOverlay() error {
	// Locate start of overlay (i.e. end of image).
	overlayStart := int64(0)
	sectHdrs, err := file.SectHeaders()
	if err != nil {
		return errors.WithStack(err)
	}
	for _, sectHdr := range sectHdrs {
		sectStart := int64(sectHdr.Offset + sectHdr.Size)
		if sectStart > overlayStart {
			overlayStart = sectStart
		}
	}
	// Locate end of overlay (i.e. end of file).
	overlayEnd, err := file.r.Seek(0, io.SeekEnd)
	if err != nil {
		return errors.WithStack(err)
	}
	overlaySize := overlayEnd - overlayStart
	overlay := make([]byte, overlaySize)
	if _, err := file.r.ReadAt(overlay, overlayStart); err != nil {
		return errors.WithStack(err)
	}
	file.overlay = overlay
	return nil
}

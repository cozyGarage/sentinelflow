// Package filetype classifies files by magic bytes rather than extension.
package filetype

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"unicode/utf8"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindText
	KindBinary
	KindELF
	KindPE
	KindMachO
	KindZip
	KindGzip
	KindTar
	KindPDF
)

func (k Kind) String() string {
	switch k {
	case KindText:
		return "text"
	case KindBinary:
		return "binary"
	case KindELF:
		return "elf"
	case KindPE:
		return "pe"
	case KindMachO:
		return "macho"
	case KindZip:
		return "zip"
	case KindGzip:
		return "gzip"
	case KindTar:
		return "tar"
	case KindPDF:
		return "pdf"
	default:
		return "unknown"
	}
}

func (k Kind) IsArchive() bool {
	return k == KindZip || k == KindGzip || k == KindTar
}

func (k Kind) IsExecutable() bool {
	return k == KindELF || k == KindPE || k == KindMachO
}

// Detect reads the first bytes of path and classifies it.
func Detect(path string) Kind {
	f, err := os.Open(path)
	if err != nil {
		return KindUnknown
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	if n <= 0 {
		return KindUnknown
	}
	return DetectBytes(buf[:n])
}

// DetectBytes classifies a header snippet.
func DetectBytes(hdr []byte) Kind {
	if len(hdr) >= 4 && hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' {
		return KindELF
	}
	if len(hdr) >= 2 && hdr[0] == 'M' && hdr[1] == 'Z' {
		return KindPE
	}
	if isMachO(hdr) {
		return KindMachO
	}
	if len(hdr) >= 4 && hdr[0] == 'P' && hdr[1] == 'K' && hdr[2] == 0x03 && hdr[3] == 0x04 {
		return KindZip
	}
	if len(hdr) >= 2 && hdr[0] == 0x1f && hdr[1] == 0x8b {
		return KindGzip
	}
	if len(hdr) >= 5 && bytes.HasPrefix(hdr, []byte("%PDF-")) {
		return KindPDF
	}
	if isTar(hdr) {
		return KindTar
	}
	if looksBinary(hdr) {
		return KindBinary
	}
	return KindText
}

func isMachO(hdr []byte) bool {
	if len(hdr) < 4 {
		return false
	}
	mag := binary.LittleEndian.Uint32(hdr[:4])
	switch mag {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return true
	}
	return false
}

func isTar(hdr []byte) bool {
	if len(hdr) >= 262 && bytes.Equal(hdr[257:262], []byte("ustar")) {
		return true
	}
	return false
}

func looksBinary(hdr []byte) bool {
	if bytes.IndexByte(hdr, 0) >= 0 {
		return true
	}
	if !utf8.Valid(hdr) {
		// Allow common latin-1; if too many non-text bytes, call it binary.
		non := 0
		for _, b := range hdr {
			if b < 0x09 || (b > 0x0d && b < 0x20) {
				non++
			}
		}
		return non > len(hdr)/8
	}
	return false
}

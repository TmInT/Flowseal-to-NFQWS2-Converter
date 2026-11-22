// mkico — генератор мульти-размерного ICO (BMP-кадры) из исходной иконки
// (PNG-в-ICO или чистый PNG). Результат: RT_ICON с ID 1..N — Wails берёт
// иконку окна из ресурса с ID 3 (winc AppIconID = 3).
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"

	"golang.org/x/image/draw"
)

var sizes = []int{16, 24, 32, 48, 64, 128, 256}

func main() {
	in := flag.String("in", "F2N.ico", "исходная иконка (.ico с PNG-кадром или .png)")
	out := flag.String("out", "icon-multi.ico", "выходной мульти-размерный .ico")
	flag.Parse()

	src, err := decodeAny(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkico:", err)
		os.Exit(1)
	}

	var ico bytes.Buffer
	ico.Write([]byte{0, 0, 1, 0})                    // reserved, type = icon
	writeU16(&ico, uint16(len(sizes)))               // count
	offset := uint32(6 + 16*len(sizes))
	var payloads [][]byte

	for _, s := range sizes {
		dst := image.NewRGBA(image.Rect(0, 0, s, s))
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
		dib := makeDIB(dst)
		ico.Write([]byte{byte(s % 256), byte(s % 256), 0, 0}) // width, height (байты! 0 = 256), colors, reserved
		writeU16(&ico, 1)                                     // planes
		writeU16(&ico, 32)                                    // bpp
		writeU32(&ico, uint32(len(dib)))
		writeU32(&ico, offset)
		payloads = append(payloads, dib)
		offset += uint32(len(dib))
	}
	for _, p := range payloads {
		ico.Write(p)
	}

	if err := os.WriteFile(*out, ico.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "mkico:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %s (%d байт, %d кадров: %v)\n", *out, ico.Len(), len(sizes), sizes)
}

// decodeAny — .ico (берёт наибольший PNG-кадр) или .png.
func decodeAny(path string) (image.Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) >= 4 && data[0] == 0x89 && data[1] == 'P' {
		return png.Decode(bytes.NewReader(data))
	}
	if len(data) >= 6 && binary.LittleEndian.Uint16(data[2:]) == 1 {
		count := int(binary.LittleEndian.Uint16(data[4:]))
		bestOff, bestLen := 0, 0
		for i := 0; i < count; i++ {
			o := 6 + 16*i
			sz := binary.LittleEndian.Uint32(data[o+8:])
			off := binary.LittleEndian.Uint32(data[o+12:])
			if int(off+sz) <= len(data) && int(sz) > bestLen {
				bestOff, bestLen = int(off), int(sz)
			}
		}
		if bestLen > 4 && data[bestOff] == 0x89 && data[bestOff+1] == 'P' {
			return png.Decode(bytes.NewReader(data[bestOff : bestOff+bestLen]))
		}
		return nil, fmt.Errorf("в %s нет PNG-кадра (BMP-кадры не поддерживаются генератором)", path)
	}
	return nil, fmt.Errorf("%s: не .ico и не .png", path)
}

// makeDIB — классический BMP-кадр ICO: BITMAPINFOHEADER(biHeight=2h) +
// XOR(BGRA, снизу вверх) + AND-маска (нули — прозрачность из альфы).
func makeDIB(src *image.RGBA) []byte {
	w := src.Bounds().Dx()
	h := src.Bounds().Dy()
	andStride := ((w + 31) / 32) * 4

	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint32(hdr[0:], 40)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(w))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(h*2))
	binary.LittleEndian.PutUint16(hdr[12:], 1)
	binary.LittleEndian.PutUint16(hdr[14:], 32)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(w*4*h+andStride*h))

	xor := make([]byte, w*4*h)
	p := 0
	for y := h - 1; y >= 0; y-- {
		row := src.Pix[y*src.Stride : y*src.Stride+w*4]
		copy(xor[p:], row)
		p += w * 4
	}
	and := make([]byte, andStride*h)

	out := make([]byte, 0, len(hdr)+len(xor)+len(and))
	out = append(out, hdr...)
	out = append(out, xor...)
	out = append(out, and...)
	return out
}

func writeU16(w *bytes.Buffer, v uint16) {
	w.Write([]byte{byte(v), byte(v >> 8)})
}

func writeU32(w *bytes.Buffer, v uint32) {
	w.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

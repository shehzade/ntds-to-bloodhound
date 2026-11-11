package registry

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"www.velocidex.com/golang/regparser"
)

var transforms = [16]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

func ExtractBootKey(systemHivePath string) ([]byte, error) {
	f, err := os.Open(systemHivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SYSTEM hive: %w", err)
	}
	defer f.Close()

	return ExtractBootKeyFromReader(f)
}

func ExtractBootKeyFromReader(reader io.ReaderAt) ([]byte, error) {
	reg, err := regparser.NewRegistry(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry hive: %w", err)
	}

	controlSet := "ControlSet001"
	selectNode := reg.OpenKey("Select")
	if selectNode != nil {
		var currentCS, defaultCS uint32
		for _, v := range selectNode.Values() {
			vd := v.ValueData()
			if len(vd.Data) >= 4 {
				switch v.ValueName() {
				case "Current":
					currentCS = binary.LittleEndian.Uint32(vd.Data)
				case "Default":
					defaultCS = binary.LittleEndian.Uint32(vd.Data)
				}
			}
		}
		if currentCS > 0 {
			controlSet = fmt.Sprintf("ControlSet%03d", currentCS)
		} else if defaultCS > 0 {
			controlSet = fmt.Sprintf("ControlSet%03d", defaultCS)
		}
	}

	var rawHex string
	subkeys := []string{"JD", "Skew1", "GBG", "Data"}
	for _, key := range subkeys {
		path := fmt.Sprintf("%s\\Control\\Lsa\\%s", controlSet, key)
		node := reg.OpenKey(path)
		if node == nil {
			return nil, fmt.Errorf("required LSA subkey not found: %s", path)
		}

		classOffset := node.Class()
		classLen := node.ClassLength()
		if classLen < 16 {
			return nil, fmt.Errorf("invalid class length for subkey %s: %d", key, classLen)
		}

		buf := make([]byte, 16)
		fileOffset := 0x1000 + int64(classOffset) + 4
		if _, err := reader.ReadAt(buf, fileOffset); err != nil {
			return nil, fmt.Errorf("failed to read class data for %s: %w", key, err)
		}

		var chars []rune
		for i := 0; i < 16; i += 2 {
			chars = append(chars, rune(binary.LittleEndian.Uint16(buf[i:i+2])))
		}
		rawHex += string(chars)
	}

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex class data: %w", err)
	}

	if len(rawBytes) != 16 {
		return nil, fmt.Errorf("expected 16 raw key bytes, got %d", len(rawBytes))
	}

	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = rawBytes[transforms[i]]
	}

	return bootKey, nil
}

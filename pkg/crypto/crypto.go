package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	EmptyLMHash = "aad3b435b51404eeaad3b435b51404ee"
	EmptyNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

type CryptoEngine struct {
	BootKey []byte
	PEKList [][]byte
}

func NewCryptoEngine(bootKey []byte) *CryptoEngine {
	return &CryptoEngine{
		BootKey: bootKey,
		PEKList: make([][]byte, 0),
	}
}

func (c *CryptoEngine) ParsePekList(pekListRaw []byte) error {
	if len(pekListRaw) < 24 {
		return errors.New("pekList blob too short")
	}

	header := pekListRaw[:8]
	keyMaterial := pekListRaw[8:24]
	encryptedPek := pekListRaw[24:]

	var decryptedPekList []byte

	if binary.LittleEndian.Uint32(header[:4]) == 0x02 {
		h := md5.New()
		h.Write(c.BootKey)
		for i := 0; i < 1000; i++ {
			h.Write(keyMaterial)
		}
		tmpKey := h.Sum(nil)
		rc4Cipher, err := rc4.NewCipher(tmpKey)
		if err != nil {
			return fmt.Errorf("failed to create RC4 cipher for PEK: %w", err)
		}
		decryptedPekList = make([]byte, len(encryptedPek))
		rc4Cipher.XORKeyStream(decryptedPekList, encryptedPek)
	} else if binary.LittleEndian.Uint32(header[:4]) == 0x03 {
		block, err := aes.NewCipher(c.BootKey)
		if err != nil {
			return fmt.Errorf("failed to create AES cipher for PEK: %w", err)
		}
		if len(encryptedPek)%aes.BlockSize != 0 {
			return fmt.Errorf("encrypted PEK size %d is not a multiple of block size", len(encryptedPek))
		}
		mode := cipher.NewCBCDecrypter(block, keyMaterial)
		decryptedPekList = make([]byte, len(encryptedPek))
		mode.CryptBlocks(decryptedPekList, encryptedPek)
	} else {
		return fmt.Errorf("unsupported PEK header version: %x", header[:4])
	}

	if len(decryptedPekList) < 32 {
		return errors.New("decrypted PEK list too short")
	}

	plainEntries := decryptedPekList[32:]
	pos := 0
	curIndex := uint32(0)

	for pos+20 <= len(plainEntries) {
		index := binary.LittleEndian.Uint32(plainEntries[pos : pos+4])
		pekKey := make([]byte, 16)
		copy(pekKey, plainEntries[pos+4:pos+20])

		if index != curIndex {
			break
		}
		c.PEKList = append(c.PEKList, pekKey)
		curIndex++
		pos += 20
	}

	if len(c.PEKList) == 0 {
		return errors.New("no valid PEK keys found in pekList")
	}

	return nil
}

func transformKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2)
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3)
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4)
	out[4] = ((in[3] & 0x0F) << 3) | (in[4] >> 5)
	out[5] = ((in[4] & 0x1F) << 2) | (in[5] >> 6)
	out[6] = ((in[5] & 0x3F) << 1) | (in[6] >> 7)
	out[7] = in[6] & 0x7F

	for i := 0; i < 8; i++ {
		out[i] = (out[i] << 1) & 0xFE
	}
	return out
}

func deriveDesKeys(rid uint32) ([]byte, []byte) {
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	k1 := []byte{ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2]}
	k2 := []byte{ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1]}

	return transformKey(k1), transformKey(k2)
}

func removeDESLayer(crypted []byte, rid uint32) ([]byte, error) {
	if len(crypted) < 16 {
		return nil, errors.New("crypted hash must be at least 16 bytes")
	}

	k1, k2 := deriveDesKeys(rid)
	c1, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 16)
	c1.Decrypt(out[:8], crypted[:8])
	c2.Decrypt(out[8:16], crypted[8:16])
	return out, nil
}

func (c *CryptoEngine) DecryptHash(encBlob []byte, rid uint32) ([]byte, error) {
	if len(c.PEKList) == 0 {
		return nil, errors.New("no PEK keys loaded")
	}
	if len(encBlob) < 24 {
		return nil, errors.New("encrypted hash blob too short")
	}

	header := encBlob[:8]
	keyMaterial := encBlob[8:24]

	pekIndexHex := hex.EncodeToString(header)
	if len(pekIndexHex) < 10 {
		return nil, errors.New("invalid header format")
	}
	pekIndex := int(header[4])
	if pekIndex >= len(c.PEKList) {
		pekIndex = 0
	}
	pek := c.PEKList[pekIndex]

	var tmpHash []byte

	if binary.LittleEndian.Uint32(header[:4]) == 0x13 {
		if len(encBlob) < 28+16 {
			return nil, errors.New("AES hash blob too short")
		}
		ciphertext := encBlob[28 : 28+16]

		block, err := aes.NewCipher(pek)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		mode := cipher.NewCBCDecrypter(block, keyMaterial)
		tmpHash = make([]byte, 16)
		mode.CryptBlocks(tmpHash, ciphertext)
	} else {
		if len(encBlob) < 24+16 {
			return nil, errors.New("RC4 hash blob too short")
		}
		ciphertext := encBlob[24 : 24+16]

		h := md5.New()
		h.Write(pek)
		h.Write(keyMaterial)
		tmpKey := h.Sum(nil)

		rc4Cipher, err := rc4.NewCipher(tmpKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create RC4 cipher: %w", err)
		}
		tmpHash = make([]byte, 16)
		rc4Cipher.XORKeyStream(tmpHash, ciphertext)
	}

	return removeDESLayer(tmpHash, rid)
}

func ParseSID(b []byte) (string, uint32, error) {
	if len(b) < 8 {
		return "", 0, errors.New("SID buffer too short")
	}

	revision := b[0]
	subAuthCount := int(b[1])
	if len(b) < 8+subAuthCount*4 {
		return "", 0, errors.New("SID buffer truncated for subauthorities")
	}

	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}
	var rid uint32

	for i := 0; i < subAuthCount; i++ {
		offset := 8 + i*4
		var subAuth uint32
		if i == subAuthCount-1 && subAuthCount > 1 {
			subAuth = binary.BigEndian.Uint32(b[offset : offset+4])
			rid = subAuth
		} else {
			subAuth = binary.LittleEndian.Uint32(b[offset : offset+4])
		}
		parts = append(parts, fmt.Sprintf("%d", subAuth))
	}

	return strings.Join(parts, "-"), rid, nil
}

func ParseBinarySID(b []byte) (string, uint32, error) {
	if len(b) < 8 {
		return "", 0, errors.New("SID buffer too short")
	}

	revision := b[0]
	subAuthCount := int(b[1])
	if revision != 1 || subAuthCount > 15 || len(b) < 8+subAuthCount*4 {
		return "", 0, errors.New("SID buffer invalid or truncated")
	}

	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}
	var rid uint32

	for i := 0; i < subAuthCount; i++ {
		offset := 8 + i*4
		subAuth := binary.LittleEndian.Uint32(b[offset : offset+4])
		if i == subAuthCount-1 {
			rid = subAuth
		}
		parts = append(parts, fmt.Sprintf("%d", subAuth))
	}

	return strings.Join(parts, "-"), rid, nil
}

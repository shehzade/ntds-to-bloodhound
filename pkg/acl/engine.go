package acl

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/Velocidex/ordereddict"
	"github.com/shehzade/ntds-to-bloodhound/pkg/ese"
)

type cacheKey struct {
	sdID    uint64
	objType string
	hasLAPS bool
}

type cachedSD struct {
	aces        []Ace
	isProtected bool
}

type SecurityEngine struct {
	RawSDs    map[uint64][]byte
	AclCache  map[cacheKey]cachedSD
	LapsGUIDs map[string]bool
}

func NewSecurityEngine(db *ese.DB) (*SecurityEngine, error) {
	engine := &SecurityEngine{
		RawSDs:    make(map[uint64][]byte),
		AclCache:  make(map[cacheKey]cachedSD),
		LapsGUIDs: make(map[string]bool),
	}

	aliases := make(map[uint64]uint64)

	err := db.StreamTable("sd_table", func(row *ordereddict.Dict) error {
		idVal, ok := row.Get("sd_id")
		if !ok || idVal == nil {
			return nil
		}

		var id uint64
		switch v := idVal.(type) {
		case uint64:
			id = v
		case int64:
			id = uint64(v)
		case uint32:
			id = uint64(v)
		case int32:
			id = uint64(v)
		case int:
			id = uint64(v)
		}

		val, _ := row.Get("sd_value")
		hexStr, ok := val.(string)
		if !ok || len(hexStr) == 0 {
			return nil
		}

		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil
		}

		if len(b) >= 20 {
			engine.RawSDs[id] = b
		} else if len(b) == 4 {
			targetID := uint64(binary.LittleEndian.Uint32(b))
			aliases[id] = targetID
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	for srcID := range aliases {
		curr := srcID
		visited := make(map[uint64]bool)
		for {
			if visited[curr] {
				break
			}
			visited[curr] = true
			if target, ok := aliases[curr]; ok {
				curr = target
			} else {
				break
			}
		}
		if rawSD, exists := engine.RawSDs[curr]; exists {
			engine.RawSDs[srcID] = rawSD
		}
	}

	return engine, nil
}

func (e *SecurityEngine) Count() int {
	return len(e.RawSDs)
}

func (e *SecurityEngine) GetAces(sdID uint64) []Ace {
	aces, _ := e.GetAcesForObject(sdID, "", false)
	return aces
}

func (e *SecurityEngine) GetAcesForObject(sdID uint64, objectType string, hasLAPS bool) ([]Ace, bool) {
	key := cacheKey{sdID: sdID, objType: objectType, hasLAPS: hasLAPS}
	if cached, exists := e.AclCache[key]; exists {
		out := make([]Ace, len(cached.aces))
		copy(out, cached.aces)
		return out, cached.isProtected
	}

	rawSD, exists := e.RawSDs[sdID]
	if !exists {
		return nil, false
	}

	aces, isProtected, err := ParseSecurityDescriptorForType(rawSD, objectType, hasLAPS, e.LapsGUIDs)
	if err != nil {
		return nil, false
	}

	e.AclCache[key] = cachedSD{aces: aces, isProtected: isProtected}
	out := make([]Ace, len(aces))
	copy(out, aces)
	return out, isProtected
}

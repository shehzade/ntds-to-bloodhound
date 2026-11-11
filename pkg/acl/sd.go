package acl

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/shehzade/ntds-to-bloodhound/pkg/crypto"
)

type Ace struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

const (
	EdgeOwns                     = "Owns"
	EdgeGenericAll               = "GenericAll"
	EdgeWriteDacl                = "WriteDacl"
	EdgeWriteOwner               = "WriteOwner"
	EdgeGenericWrite             = "GenericWrite"
	EdgeAllExtendedRights        = "AllExtendedRights"
	EdgeForceChangePassword      = "ForceChangePassword"
	EdgeGetChanges               = "GetChanges"
	EdgeGetChangesAll            = "GetChangesAll"
	EdgeGetChangesInFilteredSet  = "GetChangesInFilteredSet"
	EdgeAddMember                = "AddMember"
	EdgeAddSelf                  = "AddSelf"
	EdgeAddAllowedToAct          = "AddAllowedToAct"
	EdgeAddKeyCredentialLink     = "AddKeyCredentialLink"
	EdgeWriteSPN                 = "WriteSPN"
	EdgeWriteAccountRestrictions = "WriteAccountRestrictions"
	EdgeWriteGPLink              = "WriteGPLink"
	EdgeReadLAPSPassword         = "ReadLAPSPassword"
	EdgeReadGMSAPassword         = "ReadGMSAPassword"
)

const (
	GUIDAllZero                  = "00000000-0000-0000-0000-000000000000"
	GUIDUserForceChangePassword  = "00299570-246d-11d0-a768-00aa006e0529"
	GUIDReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDReplicationFiltered      = "89e95b76-444d-4c62-991a-0facbeda640c"
	GUIDGroupMemberAttr          = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	GUIDMembershipPropertySet    = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
	GUIDAllowedToAct             = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
	GUIDKeyCredentialLink        = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
	GUIDServicePrincipalName     = "f3a64788-5306-11d1-a9c5-0000f80367c1"
	GUIDUserAccountRestrictions  = "4c164200-20c0-11d0-a768-00aa006e0529"
	GUIDWriteGPLink              = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"

	GUIDClassUser     = "bf967aba-0de6-11d0-a285-00aa003049e2"
	GUIDClassInetOrg  = "ce206244-5827-4a86-ba1c-1c0c386c1b64"
	GUIDClassGMSA     = "7b8b558a-93a5-4af7-adca-c017e67f1057"
	GUIDClassMSA      = "febc6632-080d-422c-a779-c22712b713b0"
	GUIDClassComputer = "bf967a86-0de6-11d0-a285-00aa003049e2"
	GUIDClassGroup    = "bf967a9c-0de6-11d0-a285-00aa003049e2"
	GUIDClassDomain   = "19195a5a-6da0-11d0-afd3-00c04fd930c9"
	GUIDClassOU       = "bf967aa5-0de6-11d0-a285-00aa003049e2"
)

func isIgnoredSID(sid string) bool {
	return sid == "S-1-3-0" || sid == "S-1-5-18" || sid == "S-1-5-10"
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func inheritedGUIDApplies(inheritedGUID, objectType string) bool {
	if inheritedGUID == "" || inheritedGUID == GUIDAllZero || objectType == "" {
		return true
	}
	g := strings.ToLower(inheritedGUID)
	switch strings.ToLower(objectType) {
	case "user":
		return g == GUIDClassUser || g == GUIDClassInetOrg || g == GUIDClassGMSA || g == GUIDClassMSA
	case "computer":
		return g == GUIDClassComputer || g == GUIDClassGMSA
	case "group":
		return g == GUIDClassGroup
	case "domain":
		return g == GUIDClassDomain
	case "ou":
		return g == GUIDClassOU
	default:
		return true
	}
}

func ParseSecurityDescriptor(sdBytes []byte) ([]Ace, error) {
	aces, _, err := ParseSecurityDescriptorForType(sdBytes, "", false, nil)
	return aces, err
}

func ParseSecurityDescriptorForType(sdBytes []byte, objectType string, hasLAPS bool, lapsGUIDs map[string]bool) ([]Ace, bool, error) {
	if len(sdBytes) < 20 {
		return nil, false, nil
	}

	control := binary.LittleEndian.Uint16(sdBytes[2:4])
	isACLProtected := (control & 0x1000) != 0

	type seenKey struct {
		sid       string
		right     string
		inherited bool
	}
	seen := make(map[seenKey]bool)
	var results []Ace

	addAce := func(sid, right string, inherited bool) {
		if sid == "" || right == "" {
			return
		}
		k := seenKey{sid: sid, right: right, inherited: inherited}
		if seen[k] {
			return
		}
		seen[k] = true
		results = append(results, Ace{
			PrincipalSID:  sid,
			PrincipalType: "Base",
			RightName:     right,
			IsInherited:   inherited,
		})
	}

	objLower := strings.ToLower(objectType)

	ownerOffset := int(binary.LittleEndian.Uint32(sdBytes[4:8]))
	if objLower != "rbcd" && objLower != "gmsa" && ownerOffset >= 20 && ownerOffset+8 <= len(sdBytes) {
		ownerSID, _, err := crypto.ParseBinarySID(sdBytes[ownerOffset:])
		if err == nil && ownerSID != "" && !isIgnoredSID(ownerSID) {
			addAce(ownerSID, EdgeOwns, false)
		}
	}

	if control&0x0004 == 0 {
		return results, isACLProtected, nil
	}

	daclOffset := int(binary.LittleEndian.Uint32(sdBytes[16:20]))
	if daclOffset == 0 || daclOffset >= len(sdBytes) || daclOffset+8 > len(sdBytes) {
		return results, isACLProtected, nil
	}

	daclBytes := sdBytes[daclOffset:]
	aclSize := int(binary.LittleEndian.Uint16(daclBytes[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(daclBytes[4:6]))
	if aclSize > len(daclBytes) {
		aclSize = len(daclBytes)
	}

	offset := 8
	for i := 0; i < aceCount && offset+4 <= aclSize; i++ {
		aceType := daclBytes[offset]
		aceFlags := daclBytes[offset+1]
		aceSize := int(binary.LittleEndian.Uint16(daclBytes[offset+2 : offset+4]))
		if aceSize <= 0 || offset+aceSize > aclSize {
			break
		}

		isInherited := (aceFlags & 0x10) != 0
		isInheritOnly := (aceFlags & 0x08) != 0

		if isInheritOnly {
			offset += aceSize
			continue
		}

		if aceType == 0x00 && aceSize >= 12 {
			mask := binary.LittleEndian.Uint32(daclBytes[offset+4 : offset+8])
			sidBytes := daclBytes[offset+8 : offset+aceSize]
			principalSID, _, err := crypto.ParseBinarySID(sidBytes)
			if err == nil && principalSID != "" {
				if objLower == "rbcd" {
					if mask != 0 {
						addAce(principalSID, EdgeGenericAll, isInherited)
					}
				} else if objLower == "gmsa" {
					if mask&0x00000100 != 0 || mask&0x10000000 != 0 || mask&0x00020014 != 0 {
						addAce(principalSID, EdgeReadGMSAPassword, isInherited)
					}
				} else if !isIgnoredSID(principalSID) {
					for _, edge := range mapStandardMaskToEdges(mask, objLower, principalSID) {
						addAce(principalSID, edge, isInherited)
					}
				}
			}
		} else if aceType == 0x05 && aceSize >= 12 {
			mask := binary.LittleEndian.Uint32(daclBytes[offset+4 : offset+8])
			objFlags := binary.LittleEndian.Uint32(daclBytes[offset+8 : offset+12])
			sidOffset := offset + 12
			var objectTypeGUID string
			var inheritedTypeGUID string

			if objFlags&0x00000001 != 0 {
				if sidOffset+16 <= offset+aceSize {
					objectTypeGUID = formatGUID(daclBytes[sidOffset : sidOffset+16])
					sidOffset += 16
				}
			}
			if objFlags&0x00000002 != 0 {
				if sidOffset+16 <= offset+aceSize {
					inheritedTypeGUID = formatGUID(daclBytes[sidOffset : sidOffset+16])
					sidOffset += 16
				}
			}

			if isInherited && (objFlags&0x00000002 != 0) && !inheritedGUIDApplies(inheritedTypeGUID, objLower) {
				offset += aceSize
				continue
			}

			if sidOffset < offset+aceSize {
				sidBytes := daclBytes[sidOffset : offset+aceSize]
				principalSID, _, err := crypto.ParseBinarySID(sidBytes)
				if err == nil && principalSID != "" {
					if objLower == "rbcd" {
						if mask != 0 {
							addAce(principalSID, EdgeGenericAll, isInherited)
						}
					} else if objLower == "gmsa" {
						if mask&0x00000100 != 0 || mask&0x10000000 != 0 || mask&0x00020014 != 0 {
							addAce(principalSID, EdgeReadGMSAPassword, isInherited)
						}
					} else if !isIgnoredSID(principalSID) {
						for _, edge := range mapObjectMaskToEdges(mask, objFlags, objectTypeGUID, objLower, principalSID, hasLAPS, lapsGUIDs) {
							addAce(principalSID, edge, isInherited)
						}
					}
				}
			}
		}

		offset += aceSize
	}

	return results, isACLProtected, nil
}

func hasGenericAll(mask uint32) bool {
	return mask&0x10000000 != 0 || (mask&0x000F01FF == 0x000F01FF) || (mask&0x001F01FF == 0x001F01FF)
}

func hasGenericWrite(mask uint32) bool {
	return mask&0x40000000 != 0 || (mask&0x00020028 == 0x00020028) || mask&0x00000020 != 0
}

func mapStandardMaskToEdges(mask uint32, objType, principalSID string) []string {
	var edges []string

	if hasGenericAll(mask) {
		return []string{EdgeGenericAll}
	}

	if hasGenericWrite(mask) && objType != "domain" {
		edges = append(edges, EdgeGenericWrite)
	}
	if mask&0x00080000 != 0 {
		edges = append(edges, EdgeWriteOwner)
	}
	if mask&0x00040000 != 0 {
		edges = append(edges, EdgeWriteDacl)
	}
	if mask&0x00000100 != 0 {
		switch objType {
		case "", "user", "domain":
			edges = append(edges, EdgeAllExtendedRights)
		case "computer":
			if principalSID != "S-1-5-32-544" && !strings.HasSuffix(principalSID, "-512") {
				edges = append(edges, EdgeAllExtendedRights)
			}
		}
	}

	return edges
}

func mapObjectMaskToEdges(mask, objFlags uint32, objectGUID, objType, principalSID string, hasLAPS bool, lapsGUIDs map[string]bool) []string {
	var edges []string

	objTypePresent := (objFlags & 0x00000001) != 0
	guidLower := strings.ToLower(objectGUID)
	genericApplicable := !objTypePresent || guidLower == "" || guidLower == GUIDAllZero

	if genericApplicable {
		if hasGenericAll(mask) {
			return []string{EdgeGenericAll}
		}
		if hasGenericWrite(mask) {
			edges = append(edges, EdgeGenericWrite)
		}
		if mask&0x00040000 != 0 {
			edges = append(edges, EdgeWriteDacl)
		}
		if mask&0x00080000 != 0 {
			edges = append(edges, EdgeWriteOwner)
		}
		if mask&0x00000100 != 0 {
			switch objType {
			case "", "user", "domain":
				edges = append(edges, EdgeAllExtendedRights)
			case "computer":
				if hasLAPS {
					edges = append(edges, EdgeAllExtendedRights)
				}
			}
		}
		if (objType == "" || objType == "group") && mask&0x00000008 != 0 {
			edges = append(edges, EdgeAddSelf)
		}
		return edges
	}

	canWriteProp := mask&0x00000020 != 0 || hasGenericAll(mask) || mask&0x40000000 != 0
	hasExtRight := mask&0x00000100 != 0 || hasGenericAll(mask)

	switch guidLower {
	case GUIDGroupMemberAttr, GUIDMembershipPropertySet:
		if objType == "" || objType == "group" {
			if canWriteProp {
				edges = append(edges, EdgeAddMember)
			} else if mask&0x00000008 != 0 {
				edges = append(edges, EdgeAddSelf)
			}
		}
	case GUIDUserForceChangePassword:
		if (objType == "" || objType == "user" || objType == "computer") && hasExtRight {
			edges = append(edges, EdgeForceChangePassword)
		}
	case GUIDReplicationGetChanges:
		if (objType == "" || objType == "domain") && hasExtRight {
			edges = append(edges, EdgeGetChanges)
		}
	case GUIDReplicationGetChangesAll:
		if (objType == "" || objType == "domain") && hasExtRight {
			edges = append(edges, EdgeGetChangesAll)
		}
	case GUIDReplicationFiltered:
		if (objType == "" || objType == "domain") && hasExtRight {
			edges = append(edges, EdgeGetChangesInFilteredSet)
		}
	case GUIDAllowedToAct:
		if (objType == "" || objType == "computer") && canWriteProp {
			edges = append(edges, EdgeAddAllowedToAct)
		}
	case GUIDKeyCredentialLink:
		if (objType == "" || objType == "user" || objType == "computer") && canWriteProp {
			edges = append(edges, EdgeAddKeyCredentialLink)
		}
	case GUIDServicePrincipalName:
		if (objType == "" || objType == "user" || objType == "computer") && canWriteProp {
			edges = append(edges, EdgeWriteSPN)
		}
	case GUIDUserAccountRestrictions:
		if (objType == "" || objType == "user" || objType == "computer") && canWriteProp && !strings.HasSuffix(principalSID, "-512") {
			edges = append(edges, EdgeWriteAccountRestrictions)
		}
	case GUIDWriteGPLink:
		if (objType == "" || objType == "ou" || objType == "domain") && canWriteProp {
			edges = append(edges, EdgeWriteGPLink)
		}
	default:
		if objType == "computer" && hasLAPS && lapsGUIDs != nil && lapsGUIDs[guidLower] && (hasExtRight || mask&0x00000010 != 0) {
			edges = append(edges, EdgeReadLAPSPassword)
		}
	}

	return edges
}

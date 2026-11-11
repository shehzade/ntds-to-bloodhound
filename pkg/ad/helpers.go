package ad

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Velocidex/ordereddict"
	"github.com/shehzade/ntds-to-bloodhound/pkg/crypto"
)

type wellKnownDef struct {
	Name string
	Type string
}

var wellKnownSIDs = map[string]wellKnownDef{
	"S-1-0":        {Name: "Null Authority", Type: "User"},
	"S-1-0-0":      {Name: "Nobody", Type: "User"},
	"S-1-1":        {Name: "World Authority", Type: "User"},
	"S-1-1-0":      {Name: "Everyone", Type: "Group"},
	"S-1-2":        {Name: "Local Authority", Type: "User"},
	"S-1-2-0":      {Name: "Local", Type: "Group"},
	"S-1-2-1":      {Name: "Console Logon", Type: "Group"},
	"S-1-3":        {Name: "Creator Authority", Type: "User"},
	"S-1-3-0":      {Name: "Creator Owner", Type: "User"},
	"S-1-3-1":      {Name: "Creator Group", Type: "Group"},
	"S-1-3-2":      {Name: "Creator Owner Server", Type: "Computer"},
	"S-1-3-3":      {Name: "Creator Group Server", Type: "Computer"},
	"S-1-3-4":      {Name: "Owner Rights", Type: "Group"},
	"S-1-4":        {Name: "Non-unique Authority", Type: "User"},
	"S-1-5":        {Name: "NT Authority", Type: "User"},
	"S-1-5-1":      {Name: "Dialup", Type: "Group"},
	"S-1-5-2":      {Name: "Network", Type: "Group"},
	"S-1-5-3":      {Name: "Batch", Type: "Group"},
	"S-1-5-4":      {Name: "Interactive", Type: "Group"},
	"S-1-5-6":      {Name: "Service", Type: "Group"},
	"S-1-5-7":      {Name: "Anonymous", Type: "Group"},
	"S-1-5-8":      {Name: "Proxy", Type: "Group"},
	"S-1-5-9":      {Name: "Enterprise Domain Controllers", Type: "Group"},
	"S-1-5-10":     {Name: "Principal Self", Type: "User"},
	"S-1-5-11":     {Name: "Authenticated Users", Type: "Group"},
	"S-1-5-12":     {Name: "Restricted Code", Type: "Group"},
	"S-1-5-13":     {Name: "Terminal Server Users", Type: "Group"},
	"S-1-5-14":     {Name: "Remote Interactive Logon", Type: "Group"},
	"S-1-5-15":     {Name: "This Organization", Type: "Group"},
	"S-1-5-17":     {Name: "IUSR", Type: "User"},
	"S-1-5-18":     {Name: "Local System", Type: "User"},
	"S-1-5-19":     {Name: "NT Authority", Type: "User"},
	"S-1-5-20":     {Name: "Network Service", Type: "User"},
	"S-1-5-80-0":   {Name: "All Services", Type: "Group"},
	"S-1-5-32-544": {Name: "Administrators", Type: "Group"},
	"S-1-5-32-545": {Name: "Users", Type: "Group"},
	"S-1-5-32-546": {Name: "Guests", Type: "Group"},
	"S-1-5-32-547": {Name: "Power Users", Type: "Group"},
	"S-1-5-32-548": {Name: "Account Operators", Type: "Group"},
	"S-1-5-32-549": {Name: "Server Operators", Type: "Group"},
	"S-1-5-32-550": {Name: "Print Operators", Type: "Group"},
	"S-1-5-32-551": {Name: "Backup Operators", Type: "Group"},
	"S-1-5-32-552": {Name: "Replicators", Type: "Group"},
	"S-1-5-32-554": {Name: "Pre-Windows 2000 Compatible Access", Type: "Group"},
	"S-1-5-32-555": {Name: "Remote Desktop Users", Type: "Group"},
	"S-1-5-32-556": {Name: "Network Configuration Operators", Type: "Group"},
	"S-1-5-32-557": {Name: "Incoming Forest Trust Builders", Type: "Group"},
	"S-1-5-32-558": {Name: "Performance Monitor Users", Type: "Group"},
	"S-1-5-32-559": {Name: "Performance Log Users", Type: "Group"},
	"S-1-5-32-560": {Name: "Windows Authorization Access Group", Type: "Group"},
	"S-1-5-32-561": {Name: "Terminal Server License Servers", Type: "Group"},
	"S-1-5-32-562": {Name: "Distributed COM Users", Type: "Group"},
	"S-1-5-32-568": {Name: "IIS_IUSRS", Type: "Group"},
	"S-1-5-32-569": {Name: "Cryptographic Operators", Type: "Group"},
	"S-1-5-32-573": {Name: "Event Log Readers", Type: "Group"},
	"S-1-5-32-574": {Name: "Certificate Service DCOM Access", Type: "Group"},
	"S-1-5-32-575": {Name: "RDS Remote Access Servers", Type: "Group"},
	"S-1-5-32-576": {Name: "RDS Endpoint Servers", Type: "Group"},
	"S-1-5-32-577": {Name: "RDS Management Servers", Type: "Group"},
	"S-1-5-32-578": {Name: "Hyper-V Administrators", Type: "Group"},
	"S-1-5-32-579": {Name: "Access Control Assistance Operators", Type: "Group"},
	"S-1-5-32-580": {Name: "Remote Management Users", Type: "Group"},
	"S-1-5-32-582": {Name: "Storage Replica Administrators", Type: "Group"},
}

func functionalLevelName(level int64) string {
	switch level {
	case 0:
		return "2000 Mixed/Native"
	case 1:
		return "2003 Interim"
	case 2:
		return "2003"
	case 3:
		return "2008"
	case 4:
		return "2008 R2"
	case 5:
		return "2012"
	case 6:
		return "2012 R2"
	case 7:
		return "2016"
	default:
		if level > 7 {
			return "2016"
		}
		return "Unknown"
	}
}

func isHighValueGroupSID(rawSID string, rid uint32) bool {
	if rid == 512 || rid == 516 || rid == 519 {
		return true
	}
	switch rawSID {
	case "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551":
		return true
	}
	return false
}

func filetimeToUnix(ft int64) int64 {
	if ft <= 0 || ft == 0x7FFFFFFFFFFFFFFF {
		if ft == 0 {
			return 0
		}
		return -1
	}
	const epochDiff = int64(116444736000000000)
	if ft < epochDiff {
		return ft
	}
	return (ft - epochDiff) / 10000000
}

func readInt64(row *ordereddict.Dict, col string) (int64, bool) {
	val, ok := row.Get(col)
	if !ok || val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int64:
		return v, true
	case uint64:
		return int64(v), true
	case int32:
		return int64(v), true
	case uint32:
		return int64(v), true
	case int:
		return int64(v), true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func readUint64(row *ordereddict.Dict, col string) (uint64, bool) {
	v, ok := readInt64(row, col)
	if !ok {
		return 0, false
	}
	return uint64(v), true
}

func readString(row *ordereddict.Dict, col string) string {
	val, ok := row.Get(col)
	if !ok || val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

func readOptionalDescription(row *ordereddict.Dict) interface{} {
	s := readString(row, "ATTm13")
	if s == "" {
		return nil
	}
	return s
}

func readStringSlice(row *ordereddict.Dict, col string) []string {
	val, ok := row.Get(col)
	if !ok || val == nil {
		return make([]string, 0)
	}
	switch v := val.(type) {
	case string:
		if v == "" {
			return make([]string, 0)
		}
		return []string{v}
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return make([]string, 0)
}

func readESESIDSlice(row *ordereddict.Dict, col string) []string {
	rawVals := readStringSlice(row, col)
	if len(rawVals) == 0 {
		return nil
	}
	var out []string
	for _, hexStr := range rawVals {
		if b, err := hex.DecodeString(hexStr); err == nil {
			if s, _, err := crypto.ParseSID(b); err == nil && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func isRowDeleted(row *ordereddict.Dict, rdn string) bool {
	if delVal, ok := readInt64(row, "ATTb589872"); ok && delVal != 0 {
		return true
	}
	if strings.Contains(rdn, "\nDEL:") || strings.Contains(rdn, "\\0ADEL:") {
		return true
	}
	return false
}

func isNonDomainPartitionDN(dnUpper string) bool {
	if dnUpper == "" {
		return false
	}
	return strings.Contains(dnUpper, "CN=DELETED OBJECTS,") ||
		strings.Contains(dnUpper, "\nDEL:") ||
		strings.Contains(dnUpper, "CN=SCHEMA,") ||
		strings.Contains(dnUpper, "CN=CONFIGURATION,") ||
		strings.Contains(dnUpper, "DC=DOMAINDNSZONES,") ||
		strings.Contains(dnUpper, "DC=FORESTDNSZONES,")
}

func domainFromDN(dn string) string {
	var dcParts []string
	for _, part := range strings.Split(dn, ",") {
		p := strings.TrimSpace(part)
		if len(p) > 3 && strings.EqualFold(p[:3], "DC=") {
			comp := p[3:]
			if strings.EqualFold(comp, "DomainDnsZones") || strings.EqualFold(comp, "ForestDnsZones") {
				return ""
			}
			dcParts = append(dcParts, comp)
		}
	}
	if len(dcParts) == 0 {
		return ""
	}
	return strings.ToUpper(strings.Join(dcParts, "."))
}

func formatGUIDUpper(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func formatGUIDLower(b []byte) string {
	return strings.ToLower(formatGUIDUpper(b))
}

func extractTrustFromRow(row *ordereddict.Dict, fallbackName string) (DomainTrust, bool) {
	partner := readString(row, "ATTm590362")
	dirVal, hasDir := readInt64(row, "ATTj589956")
	typeVal, hasType := readInt64(row, "ATTj589960")
	if partner == "" && (!hasDir || !hasType) {
		return DomainTrust{}, false
	}
	if partner == "" {
		partner = readString(row, "ATTm590359")
	}
	if partner == "" {
		partner = fallbackName
	}
	if partner == "" {
		return DomainTrust{}, false
	}

	attrVal, _ := readInt64(row, "ATTj590294")
	var targetSID string
	if sidHex := readString(row, "ATTr589953"); sidHex != "" {
		if sb, err := hex.DecodeString(sidHex); err == nil {
			if s, _, err := crypto.ParseSID(sb); err == nil {
				targetSID = s
			}
		}
	}

	nonTransitive := (attrVal & 0x00000001) != 0
	quarantined := (attrVal & 0x00000004) != 0
	forestTransitive := (attrVal & 0x00000008) != 0
	crossOrg := (attrVal & 0x00000010) != 0
	withinForest := (attrVal & 0x00000020) != 0
	treatAsExternal := (attrVal & 0x00000040) != 0

	bhType := 4
	isTransitive := false
	sidFiltering := true

	if withinForest {
		bhType = 0
		isTransitive = true
		sidFiltering = quarantined
	} else if forestTransitive {
		bhType = 2
		isTransitive = true
		sidFiltering = !treatAsExternal
	} else if treatAsExternal || crossOrg || quarantined {
		bhType = 3
		isTransitive = false
		sidFiltering = true
	} else {
		if typeVal == 1 || typeVal == 2 {
			bhType = 3
		}
		isTransitive = !nonTransitive
		sidFiltering = true
	}

	return DomainTrust{
		TargetDomainName:    strings.ToUpper(partner),
		TargetDomainSid:     targetSID,
		IsTransitive:        isTransitive,
		TrustDirection:      int(dirVal),
		TrustType:           bhType,
		SidFilteringEnabled: sidFiltering,
	}, true
}

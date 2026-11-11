package ad

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Velocidex/ordereddict"
	"github.com/shehzade/ntds-to-bloodhound/pkg/acl"
	"github.com/shehzade/ntds-to-bloodhound/pkg/crypto"
	"github.com/shehzade/ntds-to-bloodhound/pkg/ese"
)

type Assembler struct {
	db             *ese.DB
	cryptoEngine   *crypto.CryptoEngine
	secEngine      *acl.SecurityEngine
	tree           *Tree
	Snapshot       *ADSnapshot
	domainOverride string

	groupsByDNT       map[uint64]*GroupObject
	ousByDNT          map[uint64]*OUObject
	deletedDNTs       map[uint64]bool
	domainDNT         uint64
	domainAces        []acl.Ace
	domainACLProtect  bool
	domainFuncLevel   string
	domainDescription interface{}
	domainTrusts      []DomainTrust
}

func NewAssembler(db *ese.DB, cryptoEngine *crypto.CryptoEngine, secEngine *acl.SecurityEngine, domainOverride string) *Assembler {
	return &Assembler{
		db:              db,
		cryptoEngine:    cryptoEngine,
		secEngine:       secEngine,
		tree:            NewTree(),
		Snapshot:        NewADSnapshot(),
		domainOverride:  strings.TrimSpace(domainOverride),
		groupsByDNT:     make(map[uint64]*GroupObject),
		ousByDNT:        make(map[uint64]*OUObject),
		deletedDNTs:     make(map[uint64]bool),
		domainFuncLevel: "2016",
		domainTrusts:    make([]DomainTrust, 0),
	}
}

func (a *Assembler) Assemble() error {
	if err := a.buildTreeAndDomain(); err != nil {
		return fmt.Errorf("failed to build tree and domain: %w", err)
	}

	if err := a.extractObjects(); err != nil {
		return fmt.Errorf("failed to extract objects: %w", err)
	}

	if err := a.processLinks(); err != nil {
		return fmt.Errorf("failed to process links: %w", err)
	}

	a.processPrimaryGroups()

	a.synthesizeWellKnownGroups()

	a.resolvePrincipalsAndAces()

	a.linkContainment()

	return nil
}

func (a *Assembler) buildTreeAndDomain() error {
	var fallbackDomainSID string
	var dcCandidateDNTs []uint64

	err := a.db.StreamTable("datatable", func(row *ordereddict.Dict) error {
		dnt, ok := readUint64(row, "DNT_col")
		if !ok || dnt == 0 {
			return nil
		}
		pdnt, _ := readUint64(row, "PDNT_col")
		a.Snapshot.PDNTByDNT[dnt] = pdnt

		if a.secEngine != nil {
			ldapName := strings.ToLower(readString(row, "ATTm131532"))
			if ldapName == "ms-mcs-admpwd" || ldapName == "mslaps-password" || ldapName == "mslaps-encryptedpassword" {
				if guidHex := readString(row, "ATTk589972"); len(guidHex) == 32 {
					if gb, err := hex.DecodeString(guidHex); err == nil && len(gb) == 16 {
						a.secEngine.LapsGUIDs[formatGUIDLower(gb)] = true
					}
				}
			}
		}

		var rdnCol string = "ATTm3"
		rdnTyp, hasRDNTyp := readInt64(row, "RDNtyp_col")
		if !hasRDNTyp {
			rdnTyp = 3
		} else {
			rdnCol = fmt.Sprintf("ATTm%d", rdnTyp)
		}

		rdn := readString(row, rdnCol)
		if rdn == "" {
			rdn = readString(row, "ATTm3")
		}
		if rdn == "" {
			rdn = readString(row, "ATTm589825")
		}
		if rdn == "" {
			rdn = readString(row, "ATTm1376281")
		}
		if rdn == "" {
			rdn = readString(row, "ATTm1376280")
		}

		if isRowDeleted(row, rdn) {
			a.deletedDNTs[dnt] = true
		}

		if sidHex := readString(row, "ATTr589970"); sidHex != "" {
			if sidBytes, err := hex.DecodeString(sidHex); err == nil {
				if sidStr, _, err := crypto.ParseSID(sidBytes); err == nil && strings.HasPrefix(sidStr, "S-1-5-21-") {
					parts := strings.Split(sidStr, "-")
					if len(parts) == 7 {
						a.Snapshot.DomainSID = sidStr
						a.domainDNT = dnt
						if lvl, hasLvl := readInt64(row, "ATTj591540"); hasLvl {
							a.domainFuncLevel = functionalLevelName(lvl)
						}
						a.domainDescription = readOptionalDescription(row)
					} else if len(parts) >= 8 && fallbackDomainSID == "" {
						fallbackDomainSID = strings.Join(parts[:7], "-")
					}
				}
			}
		}

		if rdn == "" {
			return nil
		}

		prefix := "CN="
		if rdnTyp == 1376281 || strings.HasPrefix(strings.ToLower(rdn), "dc=") {
			prefix = "DC="
			dcCandidateDNTs = append(dcCandidateDNTs, dnt)
		} else if rdnTyp == 1376280 || rdnTyp == 11 || strings.HasPrefix(strings.ToLower(rdn), "ou=") {
			prefix = "OU="
		}

		cleanRDN := rdn
		if strings.HasPrefix(strings.ToUpper(cleanRDN), prefix) {
			cleanRDN = cleanRDN[len(prefix):]
		}

		a.tree.AddNode(dnt, pdnt, cleanRDN, prefix)
		return nil
	})
	if err != nil {
		return err
	}

	if a.Snapshot.DomainSID == "" && fallbackDomainSID != "" {
		a.Snapshot.DomainSID = fallbackDomainSID
	}

	if a.domainDNT != 0 {
		if dom := domainFromDN(a.tree.ResolveDN(a.domainDNT)); dom != "" {
			a.Snapshot.DomainName = dom
		}
	}
	if a.Snapshot.DomainName == "" {
		for _, candDNT := range dcCandidateDNTs {
			if dom := domainFromDN(a.tree.ResolveDN(candDNT)); dom != "" {
				a.Snapshot.DomainName = dom
				if a.domainDNT == 0 {
					a.domainDNT = candDNT
				}
				break
			}
		}
	}

	if a.domainOverride != "" {
		a.Snapshot.DomainName = strings.ToUpper(a.domainOverride)
	}

	return nil
}

func (a *Assembler) extractSDID(row *ordereddict.Dict) (uint64, bool) {
	if sdVal := readString(row, "ATTp131353"); len(sdVal) == 16 {
		if b, err := hex.DecodeString(sdVal); err == nil && len(b) == 8 {
			return binary.LittleEndian.Uint64(b), true
		}
	}
	for _, colName := range []string{"ATTb590606", "ATTb49"} {
		if v, ok := row.Get(colName); ok && v != nil {
			switch val := v.(type) {
			case uint64:
				return val, true
			case int64:
				return uint64(val), true
			case uint32:
				return uint64(val), true
			case int32:
				return uint64(val), true
			case string:
				if len(val) == 16 {
					if b, err := hex.DecodeString(val); err == nil && len(b) == 8 {
						return binary.LittleEndian.Uint64(b), true
					}
				}
			}
		}
	}
	return 0, false
}

func (a *Assembler) resolveObjectSD(sdID uint64, foundSD bool, objType string, hasLAPS bool) ([]acl.Ace, bool) {
	if a.secEngine == nil || !foundSD {
		return make([]acl.Ace, 0), false
	}
	aces, isProtected := a.secEngine.GetAcesForObject(sdID, objType, hasLAPS)
	if aces == nil {
		aces = make([]acl.Ace, 0)
	}
	return aces, isProtected
}

func (a *Assembler) extractObjects() error {
	return a.db.StreamTable("datatable", func(row *ordereddict.Dict) error {
		dnt, ok := readUint64(row, "DNT_col")
		if !ok || dnt == 0 || a.deletedDNTs[dnt] {
			return nil
		}

		pdnt, _ := readUint64(row, "PDNT_col")
		a.Snapshot.PDNTByDNT[dnt] = pdnt

		dn := a.tree.ResolveDN(dnt)
		dnUpper := strings.ToUpper(dn)
		if isRowDeleted(row, a.tree.GetRDN(dnt)) || isNonDomainPartitionDN(dnUpper) {
			return nil
		}

		var sidStr string
		var rid uint32
		if sidHex := readString(row, "ATTr589970"); sidHex != "" {
			if sidBytes, err := hex.DecodeString(sidHex); err == nil {
				if s, r, err := crypto.ParseSID(sidBytes); err == nil {
					sidStr = s
					rid = r
				}
			}
		}

		sdID, foundSD := a.extractSDID(row)

		if dnt == a.domainDNT || (sidStr != "" && sidStr == a.Snapshot.DomainSID) {
			a.domainDNT = dnt
			a.domainAces, a.domainACLProtect = a.resolveObjectSD(sdID, foundSD, "domain", false)
		}

		if trust, isTrust := extractTrustFromRow(row, a.tree.GetRDN(dnt)); isTrust {
			a.domainTrusts = append(a.domainTrusts, trust)
			return nil
		}

		samVal, _ := row.Get("ATTm590045")
		if samVal == nil {
			rdnTyp, hasRDN := readInt64(row, "RDNtyp_col")
			if !hasRDN {
				rdnTyp = 3
			}

			var guidStr string
			if guidHex := readString(row, "ATTk589826"); len(guidHex) == 32 {
				if gb, err := hex.DecodeString(guidHex); err == nil && len(gb) == 16 {
					guidStr = formatGUIDUpper(gb)
				}
			}

			if rdnTyp == 1376280 || rdnTyp == 11 || (dnUpper != "" && strings.HasPrefix(dnUpper, "OU=")) {
				ouName := readString(row, "ATTm11")
				if ouName == "" {
					ouName = readString(row, "ATTm1376280")
				}
				if ouName == "" {
					ouName = a.tree.GetRDN(dnt)
				}
				if guidStr == "" {
					guidStr = fmt.Sprintf("OU-%d", dnt)
				}

				blocksInheritance := false
				if gpOpt, hasGP := readInt64(row, "ATTj589846"); hasGP && (gpOpt&1) != 0 {
					blocksInheritance = true
				} else if readString(row, "ATTm589846") == "1" {
					blocksInheritance = true
				}

				aces, isACLProtected := a.resolveObjectSD(sdID, foundSD, "ou", false)

				ouObj := &OUObject{
					ObjectIdentifier: guidStr,
					ChildObjects:     make([]TypedPrincipal, 0),
					Links:            make([]interface{}, 0),
					Aces:             aces,
					IsACLProtected:   isACLProtected,
					DNT:              dnt,
					PDNT:             pdnt,
					Properties: map[string]interface{}{
						"domain":            a.Snapshot.DomainName,
						"name":              fmt.Sprintf("%s@%s", strings.ToUpper(ouName), a.Snapshot.DomainName),
						"distinguishedname": dnUpper,
						"domainsid":         a.Snapshot.DomainSID,
						"highvalue":         false,
						"objectid":          guidStr,
						"blocksinheritance": blocksInheritance,
						"isaclprotected":    isACLProtected,
						"description":       readOptionalDescription(row),
					},
				}
				a.Snapshot.OUs = append(a.Snapshot.OUs, ouObj)
				a.Snapshot.OUsByGUID[guidStr] = ouObj
				a.ousByDNT[dnt] = ouObj
				a.Snapshot.ObjectsByDNT[dnt] = TypedPrincipal{ObjectIdentifier: guidStr, ObjectType: "OU"}
			}
			return nil
		}

		sam, ok := samVal.(string)
		if !ok || len(sam) == 0 || sidStr == "" {
			return nil
		}

		uacVal, _ := readInt64(row, "ATTj589832")
		uac := uint32(uacVal)

		samAccountType, _ := readInt64(row, "ATTj590126")
		if samAccountType == 805306370 || (uac&0x0800) != 0 {
			return nil
		}

		var primaryGroupID uint32 = 513
		pgInt, hasPG := readInt64(row, "ATTj589922")
		if hasPG {
			primaryGroupID = uint32(pgInt)
		}

		acInt, _ := readInt64(row, "ATTj589842")
		isAdmin := acInt > 0

		var pwdLastSet int64 = -1
		if plsInt, hasPLS := readInt64(row, "ATTq589983"); hasPLS {
			pwdLastSet = filetimeToUnix(plsInt)
		}

		var lastLogonTS int64 = -1
		if llTSInt, hasLLTS := readInt64(row, "ATTq590204"); hasLLTS {
			lastLogonTS = filetimeToUnix(llTSInt)
		}

		var lastLogon int64 = -1
		if llInt, hasLL := readInt64(row, "ATTq589876"); hasLL {
			lastLogon = filetimeToUnix(llInt)
		}

		var ntHashHex string
		if a.cryptoEngine != nil && len(a.cryptoEngine.PEKList) > 0 && rid > 0 {
			if pwdVal, ok := row.Get("ATTk589914"); ok && pwdVal != nil {
				if pwdHex, ok := pwdVal.(string); ok && len(pwdHex) > 0 {
					if encBytes, err := hex.DecodeString(pwdHex); err == nil {
						if decHash, err := a.cryptoEngine.DecryptHash(encBytes, rid); err == nil {
							ntHashHex = hex.EncodeToString(decHash)
						}
					}
				}
			}
		}

		spns := readStringSlice(row, "ATTm590595")
		delegateTargets := readStringSlice(row, "ATTm591788")
		sidHistory := readESESIDSlice(row, "ATTr590433")
		if sidHistory == nil {
			sidHistory = make([]string, 0)
		}
		desc := readOptionalDescription(row)
		gmsaHex := readString(row, "ATTk592202")
		rbcdHex := readString(row, "ATTk592023")

		_, hasLegacyLAPSExp := readInt64(row, "ATTq591790")
		_, hasWinLAPSExp := readInt64(row, "ATTq592270")
		hasLAPS := hasLegacyLAPSExp || hasWinLAPSExp || readString(row, "ATTm591789") != ""

		isGroup := samAccountType == 268435456 || samAccountType == 268435457 ||
			samAccountType == 536870912 || samAccountType == 536870913 ||
			(samAccountType == 0 && uac == 0 && !hasPG && ntHashHex == "" && !strings.HasSuffix(sam, "$"))

		isComputer := !isGroup && gmsaHex == "" &&
			(samAccountType == 805306369 || (samAccountType == 0 && strings.HasSuffix(sam, "$")))

		if isComputer {
			dnsName := readString(row, "ATTm590443")
			if dnsName == "" {
				baseHost := strings.TrimSuffix(sam, "$")
				dnsName = fmt.Sprintf("%s.%s", baseHost, a.Snapshot.DomainName)
			}

			osName := readString(row, "ATTm590187")
			osVer := readString(row, "ATTm590188")
			isDC := (uac&0x2000) != 0 || primaryGroupID == 516 || strings.Contains(dnUpper, "OU=DOMAIN CONTROLLERS,")

			aces, isACLProtected := a.resolveObjectSD(sdID, foundSD, "computer", hasLAPS)

			var rawAllowedToAct []string
			if rbcdHex != "" {
				if rbcdBytes, err := hex.DecodeString(rbcdHex); err == nil {
					rbcdAces, _, _ := acl.ParseSecurityDescriptorForType(rbcdBytes, "rbcd", false, nil)
					for _, ra := range rbcdAces {
						rawAllowedToAct = append(rawAllowedToAct, ra.PrincipalSID)
					}
				}
			}

			comp := &ComputerObject{
				ObjectIdentifier:   sidStr,
				PrimaryGroupSID:    fmt.Sprintf("%s-%d", a.Snapshot.DomainSID, primaryGroupID),
				AllowedToDelegate:  make([]TypedPrincipal, 0),
				AllowedToAct:       make([]TypedPrincipal, 0),
				HasSIDHistory:      make([]TypedPrincipal, 0),
				DumpSMSAPassword:   make([]TypedPrincipal, 0),
				Sessions:           EmptySessionCollection(),
				PrivilegedSessions: EmptySessionCollection(),
				RegistrySessions:   EmptySessionCollection(),
				LocalGroups:        make([]interface{}, 0),
				UserRights:         make([]interface{}, 0),
				Aces:               aces,
				IsACLProtected:     isACLProtected,
				IsDC:               isDC,
				DNT:                dnt,
				PDNT:               pdnt,
				NTHash:             ntHashHex,
				RawDelegateTargets: delegateTargets,
				RawAllowedToAct:    rawAllowedToAct,
				RawSIDHistory:      sidHistory,
				Properties: map[string]interface{}{
					"domain":                  a.Snapshot.DomainName,
					"name":                    strings.ToUpper(dnsName),
					"distinguishedname":       dnUpper,
					"domainsid":               a.Snapshot.DomainSID,
					"highvalue":               isDC,
					"objectid":                sidStr,
					"samaccountname":          sam,
					"enabled":                 (uac & 2) == 0,
					"haslaps":                 hasLAPS,
					"isaclprotected":          isACLProtected,
					"isdc":                    isDC,
					"operatingsystem":         osName,
					"operatingsystemversion":  osVer,
					"pwdlastset":              pwdLastSet,
					"lastlogon":               lastLogon,
					"lastlogontimestamp":      lastLogonTS,
					"unconstraineddelegation": (uac & 0x80000) != 0,
					"trustedtoauth":           (uac & 0x1000000) != 0,
					"serviceprincipalnames":   spns,
					"sidhistory":              sidHistory,
					"description":             desc,
					"nthash":                  ntHashHex,
				},
			}
			a.Snapshot.Computers = append(a.Snapshot.Computers, comp)
			a.Snapshot.ComputersBySID[sidStr] = comp
			a.Snapshot.ObjectsByDNT[dnt] = TypedPrincipal{ObjectIdentifier: sidStr, ObjectType: "Computer"}

		} else if !isGroup {
			upn := readString(row, "ATTm590480")
			aces, isACLProtected := a.resolveObjectSD(sdID, foundSD, "user", false)

			if gmsaHex != "" {
				if gmsaBytes, err := hex.DecodeString(gmsaHex); err == nil {
					gmsaAces, _, _ := acl.ParseSecurityDescriptorForType(gmsaBytes, "gmsa", false, nil)
					aces = append(aces, gmsaAces...)
				}
			}

			userName := fmt.Sprintf("%s@%s", strings.ToUpper(sam), a.Snapshot.DomainName)
			user := &UserObject{
				ObjectIdentifier:   sidStr,
				PrimaryGroupSID:    fmt.Sprintf("%s-%d", a.Snapshot.DomainSID, primaryGroupID),
				AllowedToDelegate:  make([]TypedPrincipal, 0),
				SPNTargets:         make([]interface{}, 0),
				HasSIDHistory:      make([]TypedPrincipal, 0),
				Aces:               aces,
				IsACLProtected:     isACLProtected,
				DNT:                dnt,
				PDNT:               pdnt,
				NTHash:             ntHashHex,
				RawDelegateTargets: delegateTargets,
				RawSIDHistory:      sidHistory,
				Properties: map[string]interface{}{
					"domain":                  a.Snapshot.DomainName,
					"name":                    userName,
					"distinguishedname":       dnUpper,
					"domainsid":               a.Snapshot.DomainSID,
					"highvalue":               isAdmin || rid == 500,
					"objectid":                sidStr,
					"samaccountname":          sam,
					"enabled":                 (uac & 2) == 0,
					"pwdlastset":              pwdLastSet,
					"lastlogon":               lastLogon,
					"lastlogontimestamp":      lastLogonTS,
					"userprincipalname":       upn,
					"admincount":              isAdmin,
					"dontreqpreauth":          (uac & 0x400000) != 0,
					"passwordnotreqd":         (uac & 0x20) != 0,
					"pwdneverexpires":         (uac & 0x10000) != 0,
					"sensitive":               (uac & 0x100000) != 0,
					"unconstraineddelegation": (uac & 0x80000) != 0,
					"trustedtoauth":           (uac & 0x1000000) != 0,
					"isaclprotected":          isACLProtected,
					"hasspn":                  len(spns) > 0,
					"serviceprincipalnames":   spns,
					"sidhistory":              sidHistory,
					"haslaps":                 false,
					"description":             desc,
					"nthash":                  ntHashHex,
				},
			}
			a.Snapshot.Users = append(a.Snapshot.Users, user)
			a.Snapshot.UsersBySID[sidStr] = user
			a.Snapshot.ObjectsByDNT[dnt] = TypedPrincipal{ObjectIdentifier: sidStr, ObjectType: "User"}

		} else {
			aces, isACLProtected := a.resolveObjectSD(sdID, foundSD, "group", false)
			objID := sidStr
			if _, isWK := wellKnownSIDs[sidStr]; isWK && a.Snapshot.DomainName != "" {
				objID = fmt.Sprintf("%s-%s", a.Snapshot.DomainName, sidStr)
			}

			groupName := fmt.Sprintf("%s@%s", strings.ToUpper(sam), a.Snapshot.DomainName)
			grp := &GroupObject{
				ObjectIdentifier: objID,
				Members:          make([]MemberReference, 0),
				Aces:             aces,
				IsACLProtected:   isACLProtected,
				DNT:              dnt,
				PDNT:             pdnt,
				Properties: map[string]interface{}{
					"domain":            a.Snapshot.DomainName,
					"name":              groupName,
					"distinguishedname": dnUpper,
					"domainsid":         a.Snapshot.DomainSID,
					"highvalue":         isAdmin || isHighValueGroupSID(sidStr, rid),
					"objectid":          objID,
					"samaccountname":    sam,
					"admincount":        isAdmin,
					"isaclprotected":    isACLProtected,
					"description":       desc,
				},
			}
			a.Snapshot.Groups = append(a.Snapshot.Groups, grp)
			a.Snapshot.GroupsBySID[objID] = grp
			if objID != sidStr {
				a.Snapshot.GroupsBySID[sidStr] = grp
			}
			a.groupsByDNT[dnt] = grp
			a.Snapshot.ObjectsByDNT[dnt] = TypedPrincipal{ObjectIdentifier: objID, ObjectType: "Group"}
		}

		return nil
	})
}

func (a *Assembler) processLinks() error {
	return a.db.StreamTable("link_table", func(row *ordereddict.Dict) error {
		linkBaseVal, ok := row.Get("link_base")
		if !ok || linkBaseVal == nil {
			return nil
		}

		var linkBase uint32
		switch v := linkBaseVal.(type) {
		case int32:
			linkBase = uint32(v)
		case uint32:
			linkBase = v
		case int64:
			linkBase = uint32(v)
		case uint64:
			linkBase = uint32(v)
		}
		if linkBase != 1 {
			return nil
		}

		linkDNTVal, _ := row.Get("link_DNT")
		backlinkDNTVal, _ := row.Get("backlink_DNT")
		if linkDNTVal == nil || backlinkDNTVal == nil {
			return nil
		}

		var groupDNT, memberDNT uint64
		switch v := linkDNTVal.(type) {
		case uint64:
			groupDNT = v
		case int64:
			groupDNT = uint64(v)
		case int32:
			groupDNT = uint64(v)
		case uint32:
			groupDNT = uint64(v)
		}
		switch v := backlinkDNTVal.(type) {
		case uint64:
			memberDNT = v
		case int64:
			memberDNT = uint64(v)
		case int32:
			memberDNT = uint64(v)
		case uint32:
			memberDNT = uint64(v)
		}

		grp, exists := a.groupsByDNT[groupDNT]
		if !exists {
			return nil
		}

		targetPrincipal, exists := a.Snapshot.ObjectsByDNT[memberDNT]
		if !exists || targetPrincipal.ObjectIdentifier == "" {
			return nil
		}

		for _, m := range grp.Members {
			if m.ObjectIdentifier == targetPrincipal.ObjectIdentifier {
				return nil
			}
		}

		grp.Members = append(grp.Members, MemberReference{
			ObjectIdentifier: targetPrincipal.ObjectIdentifier,
			ObjectType:       targetPrincipal.ObjectType,
		})

		return nil
	})
}

func (a *Assembler) processPrimaryGroups() {
	for _, u := range a.Snapshot.Users {
		if grp, exists := a.Snapshot.GroupsBySID[u.PrimaryGroupSID]; exists {
			alreadyMember := false
			for _, m := range grp.Members {
				if m.ObjectIdentifier == u.ObjectIdentifier {
					alreadyMember = true
					break
				}
			}
			if !alreadyMember {
				grp.Members = append(grp.Members, MemberReference{
					ObjectIdentifier: u.ObjectIdentifier,
					ObjectType:       "User",
				})
			}
		}
	}

	for _, c := range a.Snapshot.Computers {
		if grp, exists := a.Snapshot.GroupsBySID[c.PrimaryGroupSID]; exists {
			alreadyMember := false
			for _, m := range grp.Members {
				if m.ObjectIdentifier == c.ObjectIdentifier {
					alreadyMember = true
					break
				}
			}
			if !alreadyMember {
				grp.Members = append(grp.Members, MemberReference{
					ObjectIdentifier: c.ObjectIdentifier,
					ObjectType:       "Computer",
				})
			}
		}
	}

	if a.Snapshot.DomainSID != "" {
		if a.domainAces == nil {
			a.domainAces = make([]acl.Ace, 0)
		}
		domDN := fmt.Sprintf("DC=%s", strings.ReplaceAll(strings.ToUpper(a.Snapshot.DomainName), ".", ",DC="))
		domObj := &DomainObject{
			ObjectIdentifier: a.Snapshot.DomainSID,
			ChildObjects:     make([]TypedPrincipal, 0),
			Trusts:           a.domainTrusts,
			Links:            make([]interface{}, 0),
			Aces:             a.domainAces,
			IsACLProtected:   a.domainACLProtect,
			DNT:              a.domainDNT,
			Properties: map[string]interface{}{
				"domain":            a.Snapshot.DomainName,
				"name":              a.Snapshot.DomainName,
				"distinguishedname": domDN,
				"domainsid":         a.Snapshot.DomainSID,
				"highvalue":         true,
				"objectid":          a.Snapshot.DomainSID,
				"functionallevel":   a.domainFuncLevel,
				"isaclprotected":    a.domainACLProtect,
				"collected":         true,
				"description":       a.domainDescription,
			},
		}
		a.Snapshot.Domains = append(a.Snapshot.Domains, domObj)
	}
}

func (a *Assembler) synthesizeWellKnownGroups() {
	if a.Snapshot.DomainName == "" {
		return
	}

	defaults := []struct {
		rawSID string
		name   string
	}{
		{rawSID: "S-1-1-0", name: "EVERYONE"},
		{rawSID: "S-1-5-11", name: "AUTHENTICATED USERS"},
		{rawSID: "S-1-5-4", name: "INTERACTIVE"},
		{rawSID: "S-1-5-9", name: "ENTERPRISE DOMAIN CONTROLLERS"},
	}

	for _, def := range defaults {
		prefixedID := fmt.Sprintf("%s-%s", a.Snapshot.DomainName, def.rawSID)
		if _, exists := a.Snapshot.GroupsBySID[prefixedID]; exists {
			continue
		}
		if _, exists := a.Snapshot.GroupsBySID[def.rawSID]; exists {
			continue
		}

		members := make([]MemberReference, 0)
		if def.rawSID == "S-1-5-9" {
			for _, comp := range a.Snapshot.Computers {
				if comp.IsDC {
					members = append(members, MemberReference{
						ObjectIdentifier: comp.ObjectIdentifier,
						ObjectType:       "Computer",
					})
				}
			}
		}

		grp := &GroupObject{
			ObjectIdentifier: prefixedID,
			Members:          members,
			Aces:             make([]acl.Ace, 0),
			Synthetic:        true,
			Properties: map[string]interface{}{
				"domain":    a.Snapshot.DomainName,
				"domainsid": a.Snapshot.DomainSID,
				"name":      fmt.Sprintf("%s@%s", def.name, a.Snapshot.DomainName),
				"objectid":  prefixedID,
				"highvalue": false,
			},
		}
		a.Snapshot.Groups = append(a.Snapshot.Groups, grp)
		a.Snapshot.GroupsBySID[prefixedID] = grp
		a.Snapshot.GroupsBySID[def.rawSID] = grp
	}
}

func (a *Assembler) resolveSID(rawSID string) (string, string) {
	if rawSID == "" {
		return "", "Base"
	}
	if rawSID == a.Snapshot.DomainSID {
		return rawSID, "Domain"
	}
	if u, ok := a.Snapshot.UsersBySID[rawSID]; ok {
		return u.ObjectIdentifier, "User"
	}
	if c, ok := a.Snapshot.ComputersBySID[rawSID]; ok {
		return c.ObjectIdentifier, "Computer"
	}
	if g, ok := a.Snapshot.GroupsBySID[rawSID]; ok {
		return g.ObjectIdentifier, "Group"
	}
	if wk, ok := wellKnownSIDs[rawSID]; ok && a.Snapshot.DomainName != "" {
		return fmt.Sprintf("%s-%s", a.Snapshot.DomainName, rawSID), wk.Type
	}
	return rawSID, "Base"
}

func (a *Assembler) resolveDelegateSPNs(spns []string) []TypedPrincipal {
	out := make([]TypedPrincipal, 0)
	if len(spns) == 0 {
		return out
	}

	compByHost := make(map[string]*ComputerObject)
	for _, c := range a.Snapshot.Computers {
		if nameStr, ok := c.Properties["name"].(string); ok && nameStr != "" {
			upper := strings.ToUpper(nameStr)
			compByHost[upper] = c
			if idx := strings.IndexByte(upper, '.'); idx > 0 {
				compByHost[upper[:idx]] = c
			}
		}
		if samStr, ok := c.Properties["samaccountname"].(string); ok && samStr != "" {
			short := strings.ToUpper(strings.TrimSuffix(samStr, "$"))
			compByHost[short] = c
		}
	}

	seen := make(map[string]bool)
	for _, spn := range spns {
		parts := strings.SplitN(spn, "/", 2)
		if len(parts) < 2 {
			continue
		}
		host := strings.ToUpper(parts[1])
		if idx := strings.IndexByte(host, ':'); idx > 0 {
			host = host[:idx]
		}
		if idx := strings.IndexByte(host, '/'); idx > 0 {
			host = host[:idx]
		}
		comp, ok := compByHost[host]
		if !ok {
			if dot := strings.IndexByte(host, '.'); dot > 0 {
				comp, ok = compByHost[host[:dot]]
			}
		}
		if ok && comp != nil && !seen[comp.ObjectIdentifier] {
			seen[comp.ObjectIdentifier] = true
			out = append(out, TypedPrincipal{
				ObjectIdentifier: comp.ObjectIdentifier,
				ObjectType:       "Computer",
			})
		}
	}
	return out
}

func (a *Assembler) resolveSIDList(rawSIDs []string) []TypedPrincipal {
	out := make([]TypedPrincipal, 0, len(rawSIDs))
	seen := make(map[string]bool)
	for _, s := range rawSIDs {
		id, pType := a.resolveSID(s)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, TypedPrincipal{
				ObjectIdentifier: id,
				ObjectType:       pType,
			})
		}
	}
	return out
}

func (a *Assembler) rewriteAces(aces []acl.Ace) {
	for i := range aces {
		aces[i].PrincipalSID, aces[i].PrincipalType = a.resolveSID(aces[i].PrincipalSID)
	}
}

func (a *Assembler) resolvePrincipalsAndAces() {
	for _, u := range a.Snapshot.Users {
		a.rewriteAces(u.Aces)
		u.AllowedToDelegate = a.resolveDelegateSPNs(u.RawDelegateTargets)
		u.HasSIDHistory = a.resolveSIDList(u.RawSIDHistory)
	}
	for _, g := range a.Snapshot.Groups {
		a.rewriteAces(g.Aces)
	}
	for _, c := range a.Snapshot.Computers {
		a.rewriteAces(c.Aces)
		c.AllowedToDelegate = a.resolveDelegateSPNs(c.RawDelegateTargets)
		c.AllowedToAct = a.resolveSIDList(c.RawAllowedToAct)
		c.HasSIDHistory = a.resolveSIDList(c.RawSIDHistory)
	}
	for _, d := range a.Snapshot.Domains {
		a.rewriteAces(d.Aces)
	}
	for _, o := range a.Snapshot.OUs {
		a.rewriteAces(o.Aces)
	}
}

func (a *Assembler) linkContainment() {
	var rootDom *DomainObject
	if len(a.Snapshot.Domains) > 0 {
		rootDom = a.Snapshot.Domains[0]
	}

	addChild := func(pdnt uint64, childID string, childType string) {
		if childID == "" {
			return
		}
		tp := TypedPrincipal{
			ObjectIdentifier: childID,
			ObjectType:       childType,
		}

		curr := pdnt
		visited := make(map[uint64]bool)
		for curr != 0 && !visited[curr] {
			visited[curr] = true
			if ou, ok := a.ousByDNT[curr]; ok {
				ou.ChildObjects = append(ou.ChildObjects, tp)
				return
			}
			if a.domainDNT != 0 && curr == a.domainDNT {
				if rootDom != nil {
					rootDom.ChildObjects = append(rootDom.ChildObjects, tp)
				}
				return
			}
			next, exists := a.Snapshot.PDNTByDNT[curr]
			if !exists || next == curr {
				break
			}
			curr = next
		}

		if a.domainDNT == 0 && rootDom != nil {
			rootDom.ChildObjects = append(rootDom.ChildObjects, tp)
		}
	}

	for _, ou := range a.Snapshot.OUs {
		addChild(ou.PDNT, ou.ObjectIdentifier, "OU")
	}

	for _, u := range a.Snapshot.Users {
		addChild(u.PDNT, u.ObjectIdentifier, "User")
	}

	for _, c := range a.Snapshot.Computers {
		addChild(c.PDNT, c.ObjectIdentifier, "Computer")
	}

	for _, g := range a.Snapshot.Groups {
		if g.Synthetic {
			continue
		}
		addChild(g.PDNT, g.ObjectIdentifier, "Group")
	}
}

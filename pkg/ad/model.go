package ad

import "github.com/shehzade/ntds-to-bloodhound/pkg/acl"

type MemberReference struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type TypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type SessionCollection struct {
	Collected     bool          `json:"Collected"`
	FailureReason *string       `json:"FailureReason"`
	Results       []interface{} `json:"Results"`
}

func EmptySessionCollection() SessionCollection {
	return SessionCollection{
		Collected:     false,
		FailureReason: nil,
		Results:       make([]interface{}, 0),
	}
}

type DomainTrust struct {
	TargetDomainName    string
	TargetDomainSid     string
	IsTransitive        bool
	TrustDirection      int
	TrustType           int
	SidFilteringEnabled bool
}

type DomainTrustV4 struct {
	TargetDomainName    string `json:"TargetDomainName"`
	TargetDomainSid     string `json:"TargetDomainSid"`
	IsTransitive        bool   `json:"IsTransitive"`
	TrustDirection      int    `json:"TrustDirection"`
	TrustType           int    `json:"TrustType"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
}

type DomainTrustV5 struct {
	TargetDomainName    string `json:"TargetDomainName"`
	TargetDomainSid     string `json:"TargetDomainSid"`
	IsTransitive        bool   `json:"IsTransitive"`
	TrustDirection      string `json:"TrustDirection"`
	TrustType           string `json:"TrustType"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
}

func (t DomainTrust) DirectionString() string {
	switch t.TrustDirection {
	case 0:
		return "Disabled"
	case 1:
		return "Inbound"
	case 2:
		return "Outbound"
	case 3:
		return "Bidirectional"
	default:
		return "Disabled"
	}
}

func (t DomainTrust) TypeString() string {
	switch t.TrustType {
	case 0:
		return "ParentChild"
	case 1:
		return "CrossLink"
	case 2:
		return "Forest"
	case 3:
		return "External"
	default:
		return "Unknown"
	}
}

func (t DomainTrust) ToV4() DomainTrustV4 {
	return DomainTrustV4{
		TargetDomainName:    t.TargetDomainName,
		TargetDomainSid:     t.TargetDomainSid,
		IsTransitive:        t.IsTransitive,
		TrustDirection:      t.TrustDirection,
		TrustType:           t.TrustType,
		SidFilteringEnabled: t.SidFilteringEnabled,
	}
}

func (t DomainTrust) ToV5() DomainTrustV5 {
	return DomainTrustV5{
		TargetDomainName:    t.TargetDomainName,
		TargetDomainSid:     t.TargetDomainSid,
		IsTransitive:        t.IsTransitive,
		TrustDirection:      t.DirectionString(),
		TrustType:           t.TypeString(),
		SidFilteringEnabled: t.SidFilteringEnabled,
	}
}

type UserObject struct {
	ObjectIdentifier   string                 `json:"ObjectIdentifier"`
	PrimaryGroupSID    string                 `json:"PrimaryGroupSID,omitempty"`
	AllowedToDelegate  []TypedPrincipal       `json:"AllowedToDelegate"`
	SPNTargets         []interface{}          `json:"SPNTargets"`
	HasSIDHistory      []TypedPrincipal       `json:"HasSIDHistory"`
	Aces               []acl.Ace              `json:"Aces"`
	IsACLProtected     bool                   `json:"IsACLProtected"`
	IsDeleted          bool                   `json:"IsDeleted"`
	Properties         map[string]interface{} `json:"Properties"`
	DNT                uint64                 `json:"-"`
	PDNT               uint64                 `json:"-"`
	NTHash             string                 `json:"-"`
	LMHash             string                 `json:"-"`
	RawDelegateTargets []string               `json:"-"`
	RawSIDHistory      []string               `json:"-"`
}

type GroupObject struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	Members          []MemberReference      `json:"Members"`
	Aces             []acl.Ace              `json:"Aces"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
	IsDeleted        bool                   `json:"IsDeleted"`
	Properties       map[string]interface{} `json:"Properties"`
	DNT              uint64                 `json:"-"`
	PDNT             uint64                 `json:"-"`
	Synthetic        bool                   `json:"-"`
}

type ComputerObject struct {
	ObjectIdentifier   string                 `json:"ObjectIdentifier"`
	PrimaryGroupSID    string                 `json:"PrimaryGroupSID,omitempty"`
	AllowedToDelegate  []TypedPrincipal       `json:"AllowedToDelegate"`
	AllowedToAct       []TypedPrincipal       `json:"AllowedToAct"`
	HasSIDHistory      []TypedPrincipal       `json:"HasSIDHistory"`
	DumpSMSAPassword   []TypedPrincipal       `json:"DumpSMSAPassword"`
	Sessions           SessionCollection      `json:"Sessions"`
	PrivilegedSessions SessionCollection      `json:"PrivilegedSessions"`
	RegistrySessions   SessionCollection      `json:"RegistrySessions"`
	LocalGroups        []interface{}          `json:"LocalGroups"`
	UserRights         []interface{}          `json:"UserRights"`
	Aces               []acl.Ace              `json:"Aces"`
	IsACLProtected     bool                   `json:"IsACLProtected"`
	IsDeleted          bool                   `json:"IsDeleted"`
	IsDC               bool                   `json:"IsDC"`
	Status             *string                `json:"Status"`
	Properties         map[string]interface{} `json:"Properties"`
	NTHash             string                 `json:"-"`
	LMHash             string                 `json:"-"`
	DNT                uint64                 `json:"-"`
	PDNT               uint64                 `json:"-"`
	RawDelegateTargets []string               `json:"-"`
	RawAllowedToAct    []string               `json:"-"`
	RawSIDHistory      []string               `json:"-"`
}

type DomainObject struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	ChildObjects     []TypedPrincipal       `json:"ChildObjects"`
	Trusts           []DomainTrust          `json:"Trusts"`
	Links            []interface{}          `json:"Links"`
	Aces             []acl.Ace              `json:"Aces"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
	IsDeleted        bool                   `json:"IsDeleted"`
	Properties       map[string]interface{} `json:"Properties"`
	DNT              uint64                 `json:"-"`
}

type DomainObjectV4 struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	ChildObjects     []TypedPrincipal       `json:"ChildObjects"`
	Trusts           []DomainTrustV4        `json:"Trusts"`
	Links            []interface{}          `json:"Links"`
	Aces             []acl.Ace              `json:"Aces"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
	IsDeleted        bool                   `json:"IsDeleted"`
	Properties       map[string]interface{} `json:"Properties"`
}

type DomainObjectV5 struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	ChildObjects     []TypedPrincipal       `json:"ChildObjects"`
	Trusts           []DomainTrustV5        `json:"Trusts"`
	Links            []interface{}          `json:"Links"`
	Aces             []acl.Ace              `json:"Aces"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
	IsDeleted        bool                   `json:"IsDeleted"`
	Properties       map[string]interface{} `json:"Properties"`
}

func (d *DomainObject) ToV4() DomainObjectV4 {
	trusts := make([]DomainTrustV4, len(d.Trusts))
	for i, t := range d.Trusts {
		trusts[i] = t.ToV4()
	}
	return DomainObjectV4{
		ObjectIdentifier: d.ObjectIdentifier,
		ChildObjects:     d.ChildObjects,
		Trusts:           trusts,
		Links:            d.Links,
		Aces:             d.Aces,
		IsACLProtected:   d.IsACLProtected,
		IsDeleted:        d.IsDeleted,
		Properties:       d.Properties,
	}
}

func (d *DomainObject) ToV5() DomainObjectV5 {
	trusts := make([]DomainTrustV5, len(d.Trusts))
	for i, t := range d.Trusts {
		trusts[i] = t.ToV5()
	}
	return DomainObjectV5{
		ObjectIdentifier: d.ObjectIdentifier,
		ChildObjects:     d.ChildObjects,
		Trusts:           trusts,
		Links:            d.Links,
		Aces:             d.Aces,
		IsACLProtected:   d.IsACLProtected,
		IsDeleted:        d.IsDeleted,
		Properties:       d.Properties,
	}
}

type OUObject struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	ChildObjects     []TypedPrincipal       `json:"ChildObjects"`
	Links            []interface{}          `json:"Links"`
	Aces             []acl.Ace              `json:"Aces"`
	IsACLProtected   bool                   `json:"IsACLProtected"`
	IsDeleted        bool                   `json:"IsDeleted"`
	Properties       map[string]interface{} `json:"Properties"`
	DNT              uint64                 `json:"-"`
	PDNT             uint64                 `json:"-"`
}

type ADSnapshot struct {
	DomainName string
	DomainSID  string
	Users      []*UserObject
	Groups     []*GroupObject
	Computers  []*ComputerObject
	Domains    []*DomainObject
	OUs        []*OUObject

	UsersBySID     map[string]*UserObject
	GroupsBySID    map[string]*GroupObject
	ComputersBySID map[string]*ComputerObject
	OUsByGUID      map[string]*OUObject
	ObjectsByDNT   map[uint64]TypedPrincipal
	PDNTByDNT      map[uint64]uint64
}

func NewADSnapshot() *ADSnapshot {
	return &ADSnapshot{
		Users:          make([]*UserObject, 0),
		Groups:         make([]*GroupObject, 0),
		Computers:      make([]*ComputerObject, 0),
		Domains:        make([]*DomainObject, 0),
		OUs:            make([]*OUObject, 0),
		UsersBySID:     make(map[string]*UserObject),
		GroupsBySID:    make(map[string]*GroupObject),
		ComputersBySID: make(map[string]*ComputerObject),
		OUsByGUID:      make(map[string]*OUObject),
		ObjectsByDNT:   make(map[uint64]TypedPrincipal),
		PDNTByDNT:      make(map[uint64]uint64),
	}
}

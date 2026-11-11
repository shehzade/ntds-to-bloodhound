package bloodhound

type Meta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type Container struct {
	Data []interface{} `json:"data"`
	Meta Meta          `json:"meta"`
}

type FormatVersion int

const (
	Version4 FormatVersion = 4
	Version5 FormatVersion = 5
)

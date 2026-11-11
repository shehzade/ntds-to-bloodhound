package ad

import (
	"fmt"
	"strings"
)

type TreeNode struct {
	DNT    uint64
	PDNT   uint64
	RDN    string
	Prefix string
}

type Tree struct {
	nodes map[uint64]*TreeNode
}

func NewTree() *Tree {
	return &Tree{
		nodes: make(map[uint64]*TreeNode),
	}
}

func (t *Tree) AddNode(dnt, pdnt uint64, rdn, prefix string) {
	if prefix == "" {
		prefix = "CN="
	}
	t.nodes[dnt] = &TreeNode{
		DNT:    dnt,
		PDNT:   pdnt,
		RDN:    rdn,
		Prefix: prefix,
	}
}

func (t *Tree) GetRDN(dnt uint64) string {
	if n, ok := t.nodes[dnt]; ok {
		return n.RDN
	}
	return ""
}

func (t *Tree) ResolveDN(startDNT uint64) string {
	curr := startDNT
	var parts []string
	visited := make(map[uint64]bool)

	for curr != 0 && curr != 2 {
		if visited[curr] {
			break
		}
		visited[curr] = true

		node, exists := t.nodes[curr]
		if !exists || node.RDN == "" {
			break
		}

		parts = append(parts, fmt.Sprintf("%s%s", node.Prefix, node.RDN))
		if node.PDNT == 0 || node.PDNT == curr {
			break
		}
		curr = node.PDNT
	}

	return strings.Join(parts, ",")
}

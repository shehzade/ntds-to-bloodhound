package v5

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shehzade/ntds-to-bloodhound/pkg/ad"
	"github.com/shehzade/ntds-to-bloodhound/pkg/bloodhound"
)

type Writer struct {
	outDir string
}

func NewWriter(outDir string) *Writer {
	return &Writer{outDir: outDir}
}

func (w *Writer) WriteSnapshot(snap *ad.ADSnapshot) error {
	if err := os.MkdirAll(w.outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", w.outDir, err)
	}

	usersData := make([]interface{}, len(snap.Users))
	for i, u := range snap.Users {
		usersData[i] = u
	}
	if err := w.writeFile("users.json", "users", usersData); err != nil {
		return err
	}

	groupsData := make([]interface{}, len(snap.Groups))
	for i, g := range snap.Groups {
		groupsData[i] = g
	}
	if err := w.writeFile("groups.json", "groups", groupsData); err != nil {
		return err
	}

	computersData := make([]interface{}, len(snap.Computers))
	for i, c := range snap.Computers {
		computersData[i] = c
	}
	if err := w.writeFile("computers.json", "computers", computersData); err != nil {
		return err
	}

	domainsData := make([]interface{}, len(snap.Domains))
	for i, d := range snap.Domains {
		domainsData[i] = d.ToV5()
	}
	if err := w.writeFile("domains.json", "domains", domainsData); err != nil {
		return err
	}

	ousData := make([]interface{}, len(snap.OUs))
	for i, o := range snap.OUs {
		ousData[i] = o
	}
	if err := w.writeFile("ous.json", "ous", ousData); err != nil {
		return err
	}

	return nil
}

func (w *Writer) writeFile(filename, objType string, data []interface{}) error {
	container := bloodhound.Container{
		Data: data,
		Meta: bloodhound.Meta{
			Methods: 0,
			Type:    objType,
			Count:   len(data),
			Version: 5,
		},
	}

	bytes, err := json.MarshalIndent(container, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", filename, err)
	}

	filePath := filepath.Join(w.outDir, filename)
	if err := os.WriteFile(filePath, bytes, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", filePath, err)
	}

	return nil
}

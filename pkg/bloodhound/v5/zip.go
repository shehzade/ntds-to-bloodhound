package v5

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shehzade/ntds-to-bloodhound/pkg/ad"
	"github.com/shehzade/ntds-to-bloodhound/pkg/bloodhound"
)

func GenerateZipFilename() string {
	now := time.Now().UTC()
	return fmt.Sprintf("BloodHound_%s.zip", now.Format("20060102150405"))
}

func CreateZipArchive(snap *ad.ADSnapshot, targetZipPath string) error {
	dir := filepath.Dir(targetZipPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	zipFile, err := os.Create(targetZipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file %s: %w", targetZipPath, err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	writeEntry := func(filename, objType string, data []interface{}) error {
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

		w, err := zipWriter.Create(filename)
		if err != nil {
			return fmt.Errorf("failed to create zip entry %s: %w", filename, err)
		}

		if _, err := w.Write(bytes); err != nil {
			return fmt.Errorf("failed to write zip entry %s: %w", filename, err)
		}

		return nil
	}

	usersData := make([]interface{}, len(snap.Users))
	for i, u := range snap.Users {
		usersData[i] = u
	}
	if err := writeEntry("users.json", "users", usersData); err != nil {
		return err
	}

	groupsData := make([]interface{}, len(snap.Groups))
	for i, g := range snap.Groups {
		groupsData[i] = g
	}
	if err := writeEntry("groups.json", "groups", groupsData); err != nil {
		return err
	}

	computersData := make([]interface{}, len(snap.Computers))
	for i, c := range snap.Computers {
		computersData[i] = c
	}
	if err := writeEntry("computers.json", "computers", computersData); err != nil {
		return err
	}

	domainsData := make([]interface{}, len(snap.Domains))
	for i, d := range snap.Domains {
		domainsData[i] = d.ToV5()
	}
	if err := writeEntry("domains.json", "domains", domainsData); err != nil {
		return err
	}

	ousData := make([]interface{}, len(snap.OUs))
	for i, o := range snap.OUs {
		ousData[i] = o
	}
	if err := writeEntry("ous.json", "ous", ousData); err != nil {
		return err
	}

	return nil
}

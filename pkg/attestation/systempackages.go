package attestation

import "strings"

// SystemPackagesType is the type name of witness's system-packages attestor
// (https://witness.dev/attestations/system-packages/v0.1), which records the
// output of dpkg-query (or rpm) on the build machine.
const SystemPackagesType = "system-packages"

// InstalledPackage is one entry of the system-packages attestation.
type InstalledPackage struct {
	Name    string
	Version string
}

// InstalledPackages returns the installed-package list recorded by any
// system-packages attestation in atts, or nil if there is none. It lists what
// is installed on the machine, not what the build used.
func InstalledPackages(atts []TypedAttestation) []InstalledPackage {
	var out []InstalledPackage
	seen := map[string]bool{}
	for _, a := range atts {
		if a.Type != SystemPackagesType {
			continue
		}
		list, _ := a.Data["packages"].([]interface{})
		for _, item := range list {
			m, _ := item.(map[string]interface{})
			name, _ := m["name"].(string)
			version, _ := m["version"].(string)
			name = strings.TrimSpace(name)
			version = strings.TrimSpace(version)
			if name == "" || version == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, InstalledPackage{Name: name, Version: version})
		}
	}
	return out
}

// WithSystemPackages returns types plus SystemPackagesType, for parsing an
// attestation when the installed-package list is wanted too. It never
// changes which attestations files are extracted from.
func WithSystemPackages(types []string) []string {
	for _, t := range types {
		if canonicalAttestationType(t) == SystemPackagesType {
			return types
		}
	}
	return append(append([]string(nil), types...), SystemPackagesType)
}

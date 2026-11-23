package attestation

import (
	"reflect"
	"testing"
)

const systemPackagesStatement = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
  "predicate": {"name": "build", "attestations": [
    {"type": "https://witness.dev/attestations/system-packages/v0.1",
     "attestation": {"os": "linux", "distribution": "ubuntu", "version": "22.04",
       "packages": [{"name": "libc6", "version": "2.35-0ubuntu3.6"}, {"name": "apt", "version": "2.4.11"}, {"name": "", "version": "x"}]}},
    {"type": "https://witness.dev/attestations/material/v0.1", "attestation": {}}
  ]}
}`

func TestInstalledPackages(t *testing.T) {
	// The default types don't include system-packages, so it is dropped...
	atts, err := ParseWitnessData([]byte(systemPackagesStatement), []string{"material"})
	if err != nil {
		t.Fatal(err)
	}
	if got := InstalledPackages(atts); got != nil {
		t.Fatalf("not parsed, so no list expected: %v", got)
	}
	// ...unless asked for.
	atts, err = ParseWitnessData([]byte(systemPackagesStatement), WithSystemPackages([]string{"material"}))
	if err != nil {
		t.Fatal(err)
	}
	want := []InstalledPackage{{"libc6", "2.35-0ubuntu3.6"}, {"apt", "2.4.11"}}
	if got := InstalledPackages(atts); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := WithSystemPackages([]string{"material", "system-packages"}); len(got) != 2 {
		t.Fatalf("must not duplicate: %v", got)
	}
}

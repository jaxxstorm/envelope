package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
)

// CanonicalJSON returns validated JSON with all set-like collections sorted.
func (t *Topology) CanonicalJSON() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	canonical := *t
	canonical.ControllerIDs = slices.Clone(t.ControllerIDs)
	sort.Strings(canonical.ControllerIDs)

	canonical.Sites = slices.Clone(t.Sites)
	for index := range canonical.Sites {
		canonical.Sites[index].LocalPrefixes = slices.Clone(canonical.Sites[index].LocalPrefixes)
		sort.Strings(canonical.Sites[index].LocalPrefixes)
	}
	sort.Slice(canonical.Sites, func(i, j int) bool {
		return canonical.Sites[i].ID < canonical.Sites[j].ID
	})

	canonical.Routers = slices.Clone(t.Routers)
	sort.Slice(canonical.Routers, func(i, j int) bool {
		return canonical.Routers[i].ID < canonical.Routers[j].ID
	})

	canonical.Domains = slices.Clone(t.Domains)
	for index := range canonical.Domains {
		canonical.Domains[index].RemotePrefixes = slices.Clone(canonical.Domains[index].RemotePrefixes)
		sort.Strings(canonical.Domains[index].RemotePrefixes)
	}
	sort.Slice(canonical.Domains, func(i, j int) bool {
		return canonical.Domains[i].ID < canonical.Domains[j].ID
	})
	return json.Marshal(canonical)
}

// Hash returns the lowercase SHA-256 hash of CanonicalJSON.
func (t *Topology) Hash() (string, error) {
	canonical, err := t.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

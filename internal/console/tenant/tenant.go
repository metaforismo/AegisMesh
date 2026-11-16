// Package tenant validates logical isolation names before they select trusted partitions.
package tenant

import (
	"errors"
	"regexp"
	"slices"
)

// Default is the compatibility partition for existing installations.
const Default = "default"

// MaxTenants bounds process-wide partition count and therefore aggregate quotas.
const MaxTenants = 32

// ErrInvalid marks an invalid or undeclared tenant.
var ErrInvalid = errors.New("tenant: invalid or undeclared slug")

var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

// Parse accepts canonical lower-case ASCII slugs of 3..64 bytes.
func Parse(value string) (string, error) {
	if !slug.MatchString(value) {
		return "", ErrInvalid
	}
	return value, nil
}

// Names returns an independent declared set, with the compatibility default when omitted.
func Names(names []string) []string {
	if len(names) == 0 {
		return []string{Default}
	}
	return slices.Clone(names)
}

// Local returns the compatibility local partition when omitted.
func Local(name string) string {
	if name == "" {
		return Default
	}
	return name
}

// Membership returns configured membership, defaulting legacy token operators to default.
func Membership(names []string) []string { return Names(names) }

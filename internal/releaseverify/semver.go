package releaseverify

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a SemVer 2.0 triple plus optional prerelease.
// Build metadata is accepted and ignored for comparison.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

func (v Version) String() string {
	if v.Pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.Pre)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a SemVer string. A leading "v" is accepted.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, fmt.Errorf("empty version")
	}
	s = strings.TrimPrefix(s, "v")
	if s == "" || s == "dev" {
		return Version{}, fmt.Errorf("not a SemVer release: %q", s)
	}

	core := s
	pre := ""
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
		core = s
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		pre = s[i+1:]
		if pre == "" {
			return Version{}, fmt.Errorf("empty prerelease in %q", s)
		}
		if err := validatePrerelease(pre); err != nil {
			return Version{}, err
		}
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("SemVer requires major.minor.patch, got %q", s)
	}
	nums := [3]int{}
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') || strings.TrimLeft(p, "0123456789") != "" {
			return Version{}, fmt.Errorf("invalid SemVer numeric component %q", p)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("invalid SemVer numeric component %q", p)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: pre}, nil
}

func validatePrerelease(pre string) error {
	for _, id := range strings.Split(pre, ".") {
		if id == "" {
			return fmt.Errorf("empty prerelease identifier")
		}
		if strings.TrimLeft(id, "0123456789") == "" {
			if len(id) > 1 && id[0] == '0' {
				return fmt.Errorf("leading zero in numeric prerelease %q", id)
			}
			continue
		}
		for _, c := range id {
			if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '-' {
				return fmt.Errorf("invalid prerelease identifier %q", id)
			}
		}
	}
	return nil
}

// Compare returns -1 if a<b, 0 if a==b, 1 if a>b.
func Compare(a, b Version) int {
	if a.Major != b.Major {
		return cmpInt(a.Major, b.Major)
	}
	if a.Minor != b.Minor {
		return cmpInt(a.Minor, b.Minor)
	}
	if a.Patch != b.Patch {
		return cmpInt(a.Patch, b.Patch)
	}
	if a.Pre == b.Pre {
		return 0
	}
	if a.Pre == "" {
		return 1
	}
	if b.Pre == "" {
		return -1
	}
	return comparePre(a.Pre, b.Pre)
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func comparePre(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		an, aNum := parsePreID(as[i])
		bn, bNum := parsePreID(bs[i])
		if aNum && bNum {
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
			continue
		}
		if aNum && !bNum {
			return -1
		}
		if !aNum && bNum {
			return 1
		}
		if as[i] < bs[i] {
			return -1
		}
		if as[i] > bs[i] {
			return 1
		}
	}
	return cmpInt(len(as), len(bs))
}

func parsePreID(s string) (int, bool) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

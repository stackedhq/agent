package executor

import (
	"fmt"
	"regexp"
	"strings"
)

// Input validation for values that the server sends in op payloads and that
// end up in file paths, compose files, or command argv. The server validates
// the same fields; these checks are defence in depth so a compromised or buggy
// server (or a future teammate with deploy rights) cannot turn a payload field
// into a path traversal, YAML structure, or a CLI flag.

// uuidPattern matches the canonical lowercase UUID form the server uses for
// every row ID (services, databases, file mounts).
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// opIDPayloadKeys are payload fields that name an on-disk directory
// (`/opt/stacked/services/<id>`, `/opt/stacked/databases/<id>`,
// `/opt/stacked/data/services/<id>`). They are joined into paths and passed to
// RemoveAll, so they must be UUIDs before any handler runs.
var opIDPayloadKeys = []string{"serviceId", "databaseId"}

// validateOpIdentifiers rejects an op whose serviceId/databaseId is present
// but not UUID-shaped. Absent or empty fields are left to the handlers, which
// already report "requires serviceId" style errors.
func validateOpIdentifiers(payload map[string]interface{}) error {
	for _, key := range opIDPayloadKeys {
		raw, ok := payload[key]
		if !ok || raw == nil {
			continue
		}
		s, isString := raw.(string)
		if !isString {
			return fmt.Errorf("invalid %s: expected a UUID string", key)
		}
		if s == "" {
			continue
		}
		if !isUUID(s) {
			return fmt.Errorf("invalid %s %q: expected a UUID", key, truncateForError(s))
		}
	}
	return nil
}

func truncateForError(s string) string {
	const max = 80
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// Docker / OCI image reference grammar, transcribed from
// github.com/distribution/reference (regexp.go) so we don't take a dependency
// for a single regex:
//
//	reference      := name [ ":" tag ] [ "@" digest ]
//	name           := [domain '/'] remote-name
//	domain         := host [':' port-number]
//	host           := domain-name | IPv4address | \[ IPv6address \]
//	domain-name    := domain-component ['.' domain-component]*
//	domain-component := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
//	path-component := alpha-numeric [separator alpha-numeric]*
//	alpha-numeric  := /[a-z0-9]+/
//	separator      := /[_.]|__|[-]+/
//	tag            := /[\w][\w.-]{0,127}/
//	digest         := algorithm ":" hex
const (
	refAlphaNumeric    = `[a-z0-9]+`
	refSeparator       = `(?:[._]|__|[-]+)`
	refPathComponent   = refAlphaNumeric + `(?:` + refSeparator + refAlphaNumeric + `)*`
	refDomainComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`
	refDomainName      = refDomainComponent + `(?:\.` + refDomainComponent + `)*`
	refIPv6            = `\[(?:[a-fA-F0-9:]+)\]`
	refHost            = `(?:` + refDomainName + `|` + refIPv6 + `)`
	refDomain          = refHost + `(?::[0-9]+)?`
	refName            = `(?:` + refDomain + `/)?` + refPathComponent + `(?:/` + refPathComponent + `)*`
	refTag             = `[\w][\w.-]{0,127}`
	refDigest          = `[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}`
)

var imageReferencePattern = regexp.MustCompile(`^` + refName + `(?::` + refTag + `)?(?:@` + refDigest + `)?$`)

// validImageReference reports whether s is a syntactically valid docker image
// reference. The grammar cannot start with `-`, so a valid reference can never
// be parsed as a CLI flag by `docker pull` / `docker run`.
func validImageReference(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	name := s
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	// distribution/reference caps the name (without tag/digest) at 255.
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name = name[:i]
	}
	if len(name) > 255 {
		return false
	}
	return imageReferencePattern.MatchString(s)
}

func validateImageReference(s string) error {
	if !validImageReference(s) {
		return fmt.Errorf("invalid docker image reference %q", truncateForError(s))
	}
	return nil
}

// restartPolicyPattern accepts the docker/compose restart policies the server
// offers (`no`, `always`, `unless-stopped`, `on-failure`) plus the
// `on-failure:N` retry-count form docker also understands.
var restartPolicyPattern = regexp.MustCompile(`^(?:no|always|unless-stopped|on-failure(?::[0-9]{1,4})?)$`)

func validateRestartPolicy(s string) error {
	if !restartPolicyPattern.MatchString(s) {
		return fmt.Errorf("invalid restart policy %q", truncateForError(s))
	}
	return nil
}

// containerNamePattern is docker's own container-name rule.
var containerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func validateContainerName(s string) error {
	if !containerNamePattern.MatchString(s) {
		return fmt.Errorf("invalid container name %q", truncateForError(s))
	}
	return nil
}

// dbVersionPattern bounds a database engine version string (the tag part of
// the image). Agents currently receive the full image reference, whose tag is
// checked by validImageReference; this helper exists for payloads that carry
// the version separately.
var dbVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validDBVersion(s string) bool {
	return dbVersionPattern.MatchString(s)
}

// commitShaPattern is cross-branch contract 2 (lowercase hex, 7-40 chars).
var commitShaPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// normalizeCommitSha lowercases and validates a commit SHA. Empty input is
// allowed (deploy the branch tip).
func normalizeCommitSha(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if !commitShaPattern.MatchString(s) {
		return "", fmt.Errorf("invalid commit SHA %q: expected 7-40 hex characters", truncateForError(s))
	}
	return s, nil
}

// validGitBranch implements the subset of `git check-ref-format --branch`
// rules that matter for safety, plus a leading-dash ban so a branch can never
// be read as an option.
func validGitBranch(b string) bool {
	if b == "" || len(b) > 255 || b == "@" {
		return false
	}
	if strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".") || strings.HasSuffix(b, ".lock") {
		return false
	}
	if strings.Contains(b, "..") || strings.Contains(b, "@{") || strings.Contains(b, "//") {
		return false
	}
	for _, r := range b {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	for _, part := range strings.Split(b, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// envKeyPattern mirrors the server's isValidEnvVarKey.
var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

func validEnvKey(k string) bool {
	return envKeyPattern.MatchString(k)
}

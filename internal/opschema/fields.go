package opschema

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxString      = 4096
	maxCommand     = 8192
	maxURL         = 2048
	maxBody        = 64 * 1024
	maxHeadersJSON = 8 * 1024
	maxCredValue   = 1024
	maxArray       = 256
	maxVolumes     = 32
	maxFileMounts  = 20
	maxCPUMilli    = 256_000
	maxMemoryMB    = 1024 * 1024
	maxTimeoutSec  = 3600
	maxGraceSec    = 600
)

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	linuxCapRe = regexp.MustCompile(`^[A-Z0-9_]+$`)
	// Docker image reference (registry/name:tag@digest). Rejects shell/YAML metacharacters.
	imageRefRe      = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?/)?[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*(?:/[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
	dockerNameRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	networkAliasRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	extensionNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	gitBranchRe     = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	commitSHARe     = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
	semverishRe     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	identRe         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,62}$`)
	httpMethodRe    = regexp.MustCompile(`^(?:GET|POST|PUT|PATCH|DELETE|HEAD)$`)
	routePathRe     = regexp.MustCompile(`^/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@-]+)*)?$`)
)

func validUUID(s string) bool {
	return uuidRe.MatchString(s)
}

func validImageRef(s string) bool {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, " \t\n\r\"'`;&|$()<>\\") {
		return false
	}
	return imageRefRe.MatchString(s)
}

func validDockerName(s string) bool {
	return s != "" && len(s) <= 128 && dockerNameRe.MatchString(s)
}

func validRestartPolicy(s string) bool {
	switch s {
	case "no", "always", "on-failure", "unless-stopped":
		return true
	}
	return false
}

func validAccessMode(s string) bool {
	switch s {
	case "internal", "tailnet", "public":
		return true
	}
	return false
}

func validDBType(s string) bool {
	switch s {
	case "postgres", "mysql", "mongo", "redis":
		return true
	}
	return false
}

func validDeployStrategy(s string) bool {
	switch s {
	case "", "recreate", "rolling":
		return true
	}
	return false
}

func validPort(n int) bool {
	return n >= 1 && n <= 65535
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.HasPrefix(host, "*.") {
		return validHostname(host[2:])
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			isLetter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			isDigit := r >= '0' && r <= '9'
			isHyphen := r == '-'
			if !isLetter && !isDigit && !isHyphen {
				return false
			}
			if isHyphen && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}

func validUpstreamHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is empty")
	}
	for _, r := range host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("host contains whitespace or control characters")
		}
	}
	if strings.ContainsAny(host, "{}\"'#/\\") {
		return fmt.Errorf("host contains characters that are unsafe in Caddyfile upstream tokens")
	}
	addrHost := host
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
			return fmt.Errorf("invalid bracketed IPv6 host")
		}
		addrHost = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		addr, err := netip.ParseAddr(addrHost)
		if err != nil || !addr.Is6() {
			return fmt.Errorf("invalid bracketed IPv6 host")
		}
		return nil
	}
	if _, err := netip.ParseAddr(addrHost); err == nil {
		return nil
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("invalid IP literal")
	}
	if !validHostname(host) {
		return fmt.Errorf("host must be an IP literal or RFC-1123 hostname")
	}
	return nil
}

func validRoutePath(path string) bool {
	if path == "" {
		return true
	}
	if len(path) > 512 || strings.Contains(path, "..") || strings.ContainsAny(path, " \t\n\r{}\\\"#") {
		return false
	}
	return routePathRe.MatchString(path)
}

func validLinuxCapability(s string) bool {
	return s != "" && len(s) <= 64 && linuxCapRe.MatchString(s)
}

func validAbsPath(path string) bool {
	if path == "" || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	if strings.ContainsAny(path, ":,\n\r\t ") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return false
		}
	}
	return utf8.ValidString(path)
}

func validBounded(s string, max int) bool {
	return utf8.ValidString(s) && len(s) <= max && !strings.ContainsRune(s, 0)
}

func validHTTPSURL(raw string) bool {
	if raw == "" || len(raw) > maxURL {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false
	}
	return true
}

func validHTTPURL(raw string) bool {
	if raw == "" || len(raw) > maxURL {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return false
	}
	return true
}

func requireUUID(field, v string) error {
	if !validUUID(v) {
		return fmt.Errorf("%s must be a UUID", field)
	}
	return nil
}

func requireDockerName(field, v string) error {
	if !validDockerName(v) {
		return fmt.Errorf("%s is not a valid container or network name", field)
	}
	return nil
}

func optionalUUID(field, v string) error {
	if v == "" {
		return nil
	}
	return requireUUID(field, v)
}

func optionalImage(field, v string) error {
	if v == "" {
		return nil
	}
	if !validImageRef(v) {
		return fmt.Errorf("%s is not a valid image reference", field)
	}
	return nil
}

func optionalBounded(field, v string, max int) error {
	if v == "" {
		return nil
	}
	if !validBounded(v, max) {
		return fmt.Errorf("%s exceeds length or contains invalid characters", field)
	}
	return nil
}

func validNetworkAlias(s string) bool {
	return networkAliasRe.MatchString(s)
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func rejectUnknown(raw map[string]interface{}, allowed map[string]struct{}, where string) error {
	for k := range raw {
		if _, ok := allowed[k]; !ok {
			return fmt.Errorf("unknown %s field %q", where, k)
		}
	}
	return nil
}

func asObjectSlice(v interface{}, field string, max int) ([]map[string]interface{}, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	if len(arr) > max {
		return nil, fmt.Errorf("%s exceeds max length %d", field, max)
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", field, i)
		}
		out = append(out, obj)
	}
	return out, nil
}

func asStringSlice(v interface{}, field string, max int) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	if len(arr) > max {
		return nil, fmt.Errorf("%s exceeds max length %d", field, max)
	}
	out := make([]string, 0, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", field, i)
		}
		out = append(out, s)
	}
	return out, nil
}

func asStringMap(v interface{}, field string, allowedKeys map[string]struct{}) (map[string]string, error) {
	if v == nil {
		return nil, nil
	}
	raw, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	if err := rejectUnknown(raw, allowedKeys, field); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, vv := range raw {
		s, ok := vv.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s must be a string", field, k)
		}
		if !validBounded(s, maxCredValue) {
			return nil, fmt.Errorf("%s.%s is invalid", field, k)
		}
		out[k] = s
	}
	return out, nil
}

func asInt(v interface{}, field string) (int, error) {
	switch n := v.(type) {
	case nil:
		return 0, nil
	case float64:
		if n != float64(int(n)) {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
}

func asBool(v interface{}, field string) (bool, error) {
	switch b := v.(type) {
	case nil:
		return false, nil
	case bool:
		return b, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", field)
	}
}

func asString(v interface{}, field string) (string, error) {
	switch s := v.(type) {
	case nil:
		return "", nil
	case string:
		return s, nil
	default:
		return "", fmt.Errorf("%s must be a string", field)
	}
}

func credKeys() map[string]struct{} {
	return map[string]struct{}{
		"user":         {},
		"password":     {},
		"dbName":       {},
		"rootPassword": {},
	}
}

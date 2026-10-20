package executor

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// A tiny, dependency-free YAML emitter for the compose files the agent
// writes. The point is structural safety, not general YAML support:
//
//   - every string scalar is emitted as a JSON string (a valid YAML
//     double-quoted scalar), so no payload value can add YAML structure,
//     turn into a bool/number, or start a comment;
//   - every `$` in a string scalar is doubled, so Compose's variable
//     interpolation can never read the agent's environment (or anything
//     else) into the file. Compose turns `$$` back into a literal `$`.
//
// Only agent-generated tokens (numbers, `true`) use yRaw.

type yNode interface{ yamlNode() }

// yMap is an ordered mapping. Order is preserved so the output stays
// readable and stable across deploys.
type yMap []yKV

type yKV struct {
	Key   string
	Value yNode
}

// yList is a block sequence of scalars.
type yList []yNode

// yStr is a user-or-agent string, always quoted and `$`-escaped.
type yStr string

// yRaw is a trusted literal token emitted verbatim (numbers, booleans).
type yRaw string

// yNull renders as an empty value (`key:`), e.g. top-level named volumes.
type yNull struct{}

func (yMap) yamlNode()  {}
func (yList) yamlNode() {}
func (yStr) yamlNode()  {}
func (yRaw) yamlNode()  {}
func (yNull) yamlNode() {}

var yamlPlainKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// composeQuote renders s as a quoted YAML scalar with Compose interpolation
// disabled.
func composeQuote(s string) string {
	return jsonQuote(strings.ReplaceAll(s, "$", "$$"))
}

func jsonQuote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // encoding a string cannot fail
	return strings.TrimSuffix(buf.String(), "\n")
}

func yamlKey(k string) string {
	if yamlPlainKeyPattern.MatchString(k) {
		return k
	}
	return jsonQuote(k)
}

func yamlScalar(n yNode) (string, bool) {
	switch v := n.(type) {
	case yStr:
		return composeQuote(string(v)), true
	case yRaw:
		return string(v), true
	case yNull:
		return "", true
	}
	return "", false
}

// renderYAML renders a top-level mapping. Top-level sections are separated
// by a blank line, matching the hand-written templates this replaced.
func renderYAML(root yMap) string {
	var b strings.Builder
	for i, kv := range root {
		if i > 0 {
			b.WriteByte('\n')
		}
		writeYAMLEntry(&b, kv, 0)
	}
	return b.String()
}

func writeYAMLEntry(b *strings.Builder, kv yKV, indent int) {
	pad := strings.Repeat(" ", indent)
	key := yamlKey(kv.Key)
	if s, ok := yamlScalar(kv.Value); ok {
		if s == "" {
			b.WriteString(pad + key + ":\n")
		} else {
			b.WriteString(pad + key + ": " + s + "\n")
		}
		return
	}
	switch v := kv.Value.(type) {
	case yMap:
		if len(v) == 0 {
			b.WriteString(pad + key + ": {}\n")
			return
		}
		b.WriteString(pad + key + ":\n")
		for _, child := range v {
			writeYAMLEntry(b, child, indent+2)
		}
	case yList:
		if len(v) == 0 {
			b.WriteString(pad + key + ": []\n")
			return
		}
		b.WriteString(pad + key + ":\n")
		for _, item := range v {
			s, ok := yamlScalar(item)
			if !ok {
				// Lists of mappings are never generated; refuse to emit
				// something we can't render safely.
				panic("compose yaml: unsupported list item")
			}
			b.WriteString(pad + "  - " + s + "\n")
		}
	default:
		panic("compose yaml: unsupported node")
	}
}

func yStrList(items ...string) yList {
	out := make(yList, 0, len(items))
	for _, s := range items {
		out = append(out, yStr(s))
	}
	return out
}

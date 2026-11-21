package geo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxygw/internal/model"
)

// Geolocation field names used by templates, the standard schema and the
// per-field source map of model.Geo.
const (
	geoFieldCountry = "country"
	geoFieldRegion  = "region"
	geoFieldCity    = "city"
	geoFieldASN     = "asn"
	geoFieldASNOrg  = "asn_org"
	geoFieldISP     = "isp"
)

// geoFieldOrder is the stable order used when iterating fields (deterministic
// error messages and hit-path output).
var geoFieldOrder = []string{
	geoFieldCountry, geoFieldRegion, geoFieldCity, geoFieldASN, geoFieldASNOrg, geoFieldISP,
}

func validGeoFieldName(name string) bool {
	for _, f := range geoFieldOrder {
		if f == name {
			return true
		}
	}
	return false
}

// NormalizeGeo returns a copy of g with the specification normalizations
// applied: the country is upper-cased ISO 3166-1 alpha-2, textual fields are
// trimmed, a negative ASN is cleared, Provider records the contributing provider
// and UpdatedAt is set to the current UTC time when any field is populated.
func NormalizeGeo(g model.Geo, provider string) model.Geo {
	g = normalizeGeoFields(g)
	if provider != "" {
		g.Provider = provider
	}
	if !g.IsZero() {
		g.UpdatedAt = time.Now().UTC()
	}
	return g
}

// normalizeGeoFields applies the normalization rules shared by every parser.
// It does not validate the country code and does not set timestamps, which is
// the caller's job (the resolver records a per-field fetched_at).
func normalizeGeoFields(g model.Geo) model.Geo {
	g.Country = model.NormalizeCountry(g.Country)
	g.Region = strings.TrimSpace(g.Region)
	g.City = strings.TrimSpace(g.City)
	g.ASNOrg = strings.TrimSpace(g.ASNOrg)
	g.ISP = strings.TrimSpace(g.ISP)
	if g.ASN < 0 {
		g.ASN = 0
	}
	return g
}

// validateGeoFields rejects obviously wrong values instead of silently showing
// bad geolocation data (the specification forbids guessing formats).
func validateGeoFields(g model.Geo) error {
	if c := g.Country; c != "" && !isAlpha2Upper(c) {
		return fmt.Errorf("country %q is not a two-letter ISO 3166-1 alpha-2 code", c)
	}
	if g.ASN < 0 {
		return fmt.Errorf("ASN must be positive, got %d", g.ASN)
	}
	return nil
}

func isAlpha2Upper(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// LookupJSONPath evaluates the small JSONPath subset used by template providers
// against doc: "$.a.b[0].c", "$.a[0][1].b" and the equivalent bare form
// "a.b[0].c" are supported. Object keys and non-negative array indices are the
// only segment types; a malformed path, a missing key, an out-of-range index or
// a type mismatch returns a descriptive error naming the failing path.
func LookupJSONPath(doc any, path string) (any, error) {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return nil, errors.New("json path: empty path")
	}
	if strings.HasPrefix(raw, "$") {
		raw = raw[1:]
	} else if !strings.HasPrefix(raw, ".") && !strings.HasPrefix(raw, "[") {
		// Accept the bare "data.country" form used by acceptance examples.
		raw = "." + raw
	}
	cur := doc
	curPath := "$"
	for pos := 0; pos < len(raw); {
		switch raw[pos] {
		case '.':
			pos++
			start := pos
			for pos < len(raw) && raw[pos] != '.' && raw[pos] != '[' {
				pos++
			}
			key := raw[start:pos]
			if key == "" {
				return nil, fmt.Errorf("json path %q: empty object key at position %d", path, start)
			}
			obj, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("json path %q: expected an object at %s, got %s", path, curPath, jsonValueTypeName(cur))
			}
			value, exists := obj[key]
			if !exists {
				return nil, fmt.Errorf("json path %q: key %q not found at %s", path, key, curPath)
			}
			cur = value
			curPath += "." + key
		case '[':
			pos++
			start := pos
			for pos < len(raw) && raw[pos] != ']' {
				pos++
			}
			if pos >= len(raw) {
				return nil, fmt.Errorf("json path %q: unterminated array index", path)
			}
			indexText := strings.TrimSpace(raw[start:pos])
			pos++ // consume ']'
			index, err := strconv.Atoi(indexText)
			if err != nil || index < 0 {
				return nil, fmt.Errorf("json path %q: invalid array index %q (only non-negative integers are supported)", path, indexText)
			}
			array, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("json path %q: expected an array at %s, got %s", path, curPath, jsonValueTypeName(cur))
			}
			if index >= len(array) {
				return nil, fmt.Errorf("json path %q: index %d out of range at %s (array length %d)", path, index, curPath, len(array))
			}
			cur = array[index]
			curPath += fmt.Sprintf("[%d]", index)
		default:
			return nil, fmt.Errorf("json path %q: unexpected %q at position %d (expected '.' or '[')", path, raw[pos], pos)
		}
	}
	return cur, nil
}

// ApplyTemplateFields maps a provider response onto model.Geo using the
// declarative field mappings of a template provider. A mapping is either a
// JSONPath expression ("$.a.b[0]") or "regex:<pattern>" for plain text
// responses; regex mappings use capture group 1 when present. The second return
// value records, per field, which mapping produced the value (shown by the
// panel test button). Missing paths, type mismatches, empty values and
// non-matching regexes are hard errors: a mapping is never silently skipped.
func ApplyTemplateFields(body []byte, fields map[string]string) (model.Geo, map[string]string, error) {
	if len(fields) == 0 {
		return model.Geo{}, nil, errors.New("template: no field mappings configured")
	}
	keys := make([]string, 0, len(fields))
	for field := range fields {
		keys = append(keys, field)
	}
	sort.Strings(keys)

	type compiledField struct {
		mapping string
		re      *regexp.Regexp
		path    string
	}
	specs := make(map[string]compiledField, len(fields))
	needJSON := false
	for _, field := range keys {
		mapping := strings.TrimSpace(fields[field])
		switch {
		case !validGeoFieldName(field):
			return model.Geo{}, nil, fmt.Errorf("template: unsupported field %q (supported: country, region, city, asn, asn_org, isp)", field)
		case mapping == "":
			return model.Geo{}, nil, fmt.Errorf("template: field %q has an empty mapping", field)
		case strings.HasPrefix(mapping, "regex:"):
			pattern := strings.TrimPrefix(mapping, "regex:")
			if pattern == "" {
				return model.Geo{}, nil, fmt.Errorf("template: field %q: empty regex pattern", field)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return model.Geo{}, nil, fmt.Errorf("template: field %q: invalid regex %q: %w", field, pattern, err)
			}
			specs[field] = compiledField{mapping: mapping, re: re}
		default:
			needJSON = true
			specs[field] = compiledField{mapping: mapping, path: mapping}
		}
	}

	var doc any
	if needJSON {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return model.Geo{}, nil, fmt.Errorf("template: response is not valid JSON while JSON field mappings are configured: %w", err)
		}
		if err := ensureJSONEOF(dec); err != nil {
			return model.Geo{}, nil, fmt.Errorf("template: response is not valid JSON while JSON field mappings are configured: %w", err)
		}
	}

	geo := model.Geo{}
	hitPaths := make(map[string]string, len(fields))
	for _, field := range keys {
		spec := specs[field]
		var value any
		if spec.re != nil {
			match := spec.re.FindSubmatch(body)
			if match == nil {
				return model.Geo{}, nil, fmt.Errorf("template: field %q: regex %q did not match the response", field, strings.TrimPrefix(spec.mapping, "regex:"))
			}
			if len(match) >= 2 {
				value = string(match[1])
			} else {
				value = string(match[0])
			}
		} else {
			got, err := LookupJSONPath(doc, spec.path)
			if err != nil {
				return model.Geo{}, nil, fmt.Errorf("template: field %q: %w", field, err)
			}
			value = got
		}
		if err := assignGeoField(&geo, field, value); err != nil {
			return model.Geo{}, nil, fmt.Errorf("template: field %q: %w", field, err)
		}
		hitPaths[field] = spec.mapping
	}
	geo = normalizeGeoFields(geo)
	if err := validateGeoFields(geo); err != nil {
		return model.Geo{}, nil, fmt.Errorf("template: %w", err)
	}
	return geo, hitPaths, nil
}

// ParseSchema parses the project standard JSON schema returned by "schema"
// providers:
//
//	{"country":"JP","region":"Tokyo","city":"Tokyo","asn":2516,"asn_org":"KDDI","isp":"KDDI"}
//
// Every field may be omitted or null. "asn" accepts an integer or an "AS123"
// string. Unknown additional fields are ignored, but wrong types and malformed
// JSON are hard errors: the response format is never guessed.
func ParseSchema(body []byte) (model.Geo, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return model.Geo{}, errors.New("schema: empty response body")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return model.Geo{}, fmt.Errorf("schema: response is not a valid JSON object: %w", err)
	}
	if raw == nil {
		return model.Geo{}, errors.New("schema: response must be a JSON object")
	}
	if err := ensureJSONEOF(dec); err != nil {
		return model.Geo{}, fmt.Errorf("schema: unexpected trailing data after the JSON object: %w", err)
	}
	geo := model.Geo{}
	keys := make([]string, 0, len(raw))
	for field := range raw {
		keys = append(keys, field)
	}
	sort.Strings(keys)
	for _, field := range keys {
		value := raw[field]
		switch field {
		case geoFieldCountry, geoFieldRegion, geoFieldCity, geoFieldASNOrg, geoFieldISP:
			text, err := schemaString(value, field)
			if err != nil {
				return model.Geo{}, err
			}
			if text == "" {
				continue
			}
			if err := assignGeoField(&geo, field, text); err != nil {
				return model.Geo{}, fmt.Errorf("schema: field %q: %w", field, err)
			}
		case geoFieldASN:
			asn, err := schemaASN(value)
			if err != nil {
				return model.Geo{}, fmt.Errorf("schema: field %q: %w", field, err)
			}
			geo.ASN = asn
		default:
			// Forward compatible: unknown fields are ignored, never guessed.
		}
	}
	return normalizeSchemaGeo(geo)
}

// normalizeSchemaGeo applies normalization and schema-level validation.
func normalizeSchemaGeo(geo model.Geo) (model.Geo, error) {
	geo = normalizeGeoFields(geo)
	if err := validateGeoFields(geo); err != nil {
		return model.Geo{}, fmt.Errorf("schema: %w", err)
	}
	return geo, nil
}

// ensureJSONEOF rejects trailing non-whitespace data after the first value.
func ensureJSONEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}

// schemaString extracts an optional string field of the standard schema. null
// and absent are treated alike.
func schemaString(raw json.RawMessage, field string) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil
	}
	if trimmed[0] != '"' {
		return "", fmt.Errorf("schema: field %q: expected a string, got %s", field, jsonRawTypeName(trimmed))
	}
	var text string
	if err := json.Unmarshal(trimmed, &text); err != nil {
		return "", fmt.Errorf("schema: field %q: %w", field, err)
	}
	return strings.TrimSpace(text), nil
}

// schemaASN extracts the optional "asn" field, accepting an integer or an
// "AS123" string.
func schemaASN(raw json.RawMessage) (int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, nil
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return 0, err
	}
	asn, err := asnFromAny(value)
	if err != nil {
		return 0, err
	}
	return asn, nil
}

// assignGeoField stores one parsed value, enforcing the documented value types.
func assignGeoField(geo *model.Geo, field string, value any) error {
	switch field {
	case geoFieldCountry, geoFieldRegion, geoFieldCity, geoFieldASNOrg, geoFieldISP:
		text, err := stringValue(value)
		if err != nil {
			return err
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return errors.New("value is empty")
		}
		switch field {
		case geoFieldCountry:
			geo.Country = text
		case geoFieldRegion:
			geo.Region = text
		case geoFieldCity:
			geo.City = text
		case geoFieldASNOrg:
			geo.ASNOrg = text
		case geoFieldISP:
			geo.ISP = text
		}
		return nil
	case geoFieldASN:
		asn, err := asnFromAny(value)
		if err != nil {
			return err
		}
		geo.ASN = asn
		return nil
	default:
		return fmt.Errorf("unsupported field %q", field)
	}
}

// stringValue converts a parsed JSON value to a string for the textual fields.
// Only real JSON strings are accepted: a number where a country/ISP string is
// expected is a configuration error, not something to guess.
func stringValue(value any) (string, error) {
	if text, ok := value.(string); ok {
		return text, nil
	}
	return "", fmt.Errorf("expected a string, got %s", jsonValueTypeName(value))
}

// asnFromAny converts an "AS123" string or an integer value to the integer ASN
// representation ("AS" prefix removed).
func asnFromAny(value any) (int, error) {
	switch v := value.(type) {
	case string:
		asn, err := model.NormalizeASN(v)
		if err != nil {
			return 0, fmt.Errorf("invalid ASN %q: %w", strings.TrimSpace(v), err)
		}
		return asn, nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("expected an integer ASN, got %q", v.String())
		}
		if i <= 0 {
			return 0, fmt.Errorf("expected a positive ASN, got %d", i)
		}
		return int(i), nil
	case float64:
		if v != math.Trunc(v) || v <= 0 || v > math.MaxInt32 {
			return 0, fmt.Errorf("expected a positive integer ASN, got %v", v)
		}
		return int(v), nil
	case int:
		if v <= 0 {
			return 0, fmt.Errorf("expected a positive ASN, got %d", v)
		}
		return v, nil
	case int64:
		if v <= 0 {
			return 0, fmt.Errorf("expected a positive ASN, got %d", v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("expected an integer or an \"AS<number>\" string, got %s", jsonValueTypeName(value))
	}
}

// splitASNOrg splits an organization string such as "AS15169 Google LLC" into
// the integer ASN and the organization name. Strings without an ASN prefix are
// kept verbatim as the organization.
func splitASNOrg(org string) (int, string) {
	org = strings.TrimSpace(org)
	if org == "" {
		return 0, ""
	}
	first, rest, _ := strings.Cut(org, " ")
	asn, err := model.NormalizeASN(first)
	if err != nil {
		return 0, org
	}
	return asn, strings.TrimSpace(rest)
}

// jsonValueTypeName names the JSON type of a decoded value for error messages.
func jsonValueTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number, float64, float32, int, int64:
		return "number"
	case bool:
		return "boolean"
	default:
		return fmt.Sprintf("%T", value)
	}
}

// jsonRawTypeName names the JSON type of a raw JSON fragment.
func jsonRawTypeName(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "empty"
	}
	switch trimmed[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

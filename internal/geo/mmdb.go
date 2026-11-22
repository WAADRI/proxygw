package geo

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"proxygw/internal/model"
)

// The local MMDB layer accepts both the nested MaxMind GeoLite2/GeoIP2 layout
// and the flat layouts used by several compatible providers (for example
// IPLocate, whose "country" field is the full country name and whose
// "country_code" field carries the ISO code). Records are decoded into a
// generic map instead of a rigid struct so a single unexpected field type can
// never make the whole lookup fail.
//
// Example shapes handled:
//
//	MaxMind:  {"country":{"iso_code":"US"}, "city":{"names":{"en":"..."}}}
//	IPLocate: {"country":"United States", "country_code":"US"}
//	DB-IP:    {"country":"DE", "region":"Berlin", "city":"Berlin"}
//
// Missing or unexpected fields are ignored, not guessed.

// mmdbLayer is the local MaxMind DB primary geolocation layer. A missing or
// corrupt database is not fatal: the layer is kept with loadErr set so the panel
// shows the provider as unhealthy and node registration still works with online
// providers or an unknown region.
type mmdbLayer struct {
	names    []string // provider names that refer to the local MMDB
	path     string
	primary  string
	priority int

	mu      sync.Mutex
	reader  *maxminddb.Reader
	loadErr error
	enabled bool

	// testLookup is a test-only hook (same package tests) letting the resolver
	// partial-fill tests exercise the MMDB primary layer without a real MMDB
	// file. It is always nil in production.
	testLookup func(net.IP) (model.Geo, map[string]string, error)
}

// newMMDBLayer opens the configured MMDB (when path is non-empty) and returns a
// layer that never fails construction.
func newMMDBLayer(path string, names []string, priority int) *mmdbLayer {
	layer := &mmdbLayer{path: path, names: names, priority: priority, enabled: true}
	if len(names) > 0 {
		layer.primary = names[0]
	} else {
		layer.primary = presetMMDB
	}
	if path == "" {
		layer.loadErr = errors.New("geo.mmdb_path is not configured")
		return layer
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		layer.loadErr = fmt.Errorf("open %s: %w", path, err)
		return layer
	}
	layer.reader = reader
	return layer
}

// hasName reports whether name addresses the local MMDB layer.
func (m *mmdbLayer) hasName(name string) bool {
	if m == nil {
		return false
	}
	for _, n := range m.names {
		if n == name {
			return true
		}
	}
	return false
}

// primaryName is the name recorded as the field source.
func (m *mmdbLayer) primaryName() string {
	if m == nil || m.primary == "" {
		return presetMMDB
	}
	return m.primary
}

// isEnabled reports whether the layer is currently allowed to contribute.
func (m *mmdbLayer) isEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled && (m.reader != nil || m.testLookup != nil)
}

// lookup resolves one IP against the local database.
func (m *mmdbLayer) lookup(ip net.IP) (model.Geo, map[string]string, error) {
	if m == nil {
		return model.Geo{}, nil, errors.New("mmdb unavailable")
	}
	m.mu.Lock()
	reader := m.reader
	loadErr := m.loadErr
	testLookup := m.testLookup
	m.mu.Unlock()
	if testLookup != nil {
		return testLookup(ip)
	}
	if reader == nil {
		if loadErr != nil {
			return model.Geo{}, nil, fmt.Errorf("mmdb unavailable: %w", loadErr)
		}
		return model.Geo{}, nil, errors.New("mmdb unavailable")
	}
	var record map[string]any
	if err := reader.Lookup(ip, &record); err != nil {
		return model.Geo{}, nil, fmt.Errorf("mmdb lookup %s: %w", ip, err)
	}
	return geoFromMMDBMap(record)
}

// geoFromMMDBMap maps a decoded MMDB record to the normalized Geo model.
func geoFromMMDBMap(record map[string]any) (model.Geo, map[string]string, error) {
	geo := model.Geo{}
	hitPaths := map[string]string{}
	if country, path := mmdbCountry(record); country != "" {
		geo.Country = country
		hitPaths[geoFieldCountry] = path
	}
	if region, path := mmdbRegion(record); region != "" {
		geo.Region = region
		hitPaths[geoFieldRegion] = path
	}
	if city, path := mmdbCity(record); city != "" {
		geo.City = city
		hitPaths[geoFieldCity] = path
	}
	if asn, path := mmdbASN(record); asn > 0 {
		geo.ASN = asn
		hitPaths[geoFieldASN] = path
	}
	if org, path := mmdbTextFrom(record,
		"autonomous_system_organization", "as_name", "as_org", "organization", "org"); org != "" {
		geo.ASNOrg = org
		hitPaths[geoFieldASNOrg] = path
	}
	if isp, path := mmdbTextFrom(record, "isp"); isp != "" {
		geo.ISP = isp
		hitPaths[geoFieldISP] = path
	}
	return normalizeGeoFields(geo), hitPaths, nil
}

// mmdbCountry extracts the ISO 3166-1 alpha-2 country code.
func mmdbCountry(record map[string]any) (string, string) {
	if country := mmdbMap(record["country"]); country != nil {
		for _, key := range []string{"iso_code", "code"} {
			if code := mmdbCountryCode(mmdbText(country[key])); code != "" {
				return code, "country." + key
			}
		}
	}
	if code := mmdbCountryCode(mmdbText(record["country"])); code != "" {
		return code, "country"
	}
	for _, key := range []string{"country_code", "countryCode", "country_iso_code", "iso_code"} {
		if code := mmdbCountryCode(mmdbText(record[key])); code != "" {
			return code, key
		}
	}
	if country := mmdbMap(record["registered_country"]); country != nil {
		for _, key := range []string{"iso_code", "code"} {
			if code := mmdbCountryCode(mmdbText(country[key])); code != "" {
				return code, "registered_country." + key
			}
		}
	}
	return "", ""
}

// mmdbRegion extracts the most specific first-level region name.
func mmdbRegion(record map[string]any) (string, string) {
	if items, ok := record["subdivisions"].([]any); ok && len(items) > 0 {
		if subdivision := mmdbMap(items[0]); subdivision != nil {
			if name, suffix := mmdbNameFromObject(subdivision); name != "" {
				return name, "subdivisions[0]." + suffix
			}
			if code := mmdbText(subdivision["iso_code"]); code != "" {
				return code, "subdivisions[0].iso_code"
			}
		}
	}
	if subdivision := mmdbMap(record["subdivision"]); subdivision != nil {
		if name, suffix := mmdbNameFromObject(subdivision); name != "" {
			return name, "subdivision." + suffix
		}
	}
	return mmdbTextFrom(record, "region", "region_name", "region_code", "state", "state_name")
}

// mmdbCity extracts the city name.
func mmdbCity(record map[string]any) (string, string) {
	if city := mmdbMap(record["city"]); city != nil {
		if name, suffix := mmdbNameFromObject(city); name != "" {
			return name, "city." + suffix
		}
	}
	if city := mmdbText(record["city"]); city != "" {
		return city, "city"
	}
	return mmdbTextFrom(record, "city_name", "cityName")
}

// mmdbASN extracts the integer ASN from numeric or "AS123" style values.
func mmdbASN(record map[string]any) (int, string) {
	for _, key := range []string{"autonomous_system_number", "asn", "as_number"} {
		value, ok := record[key]
		if !ok {
			continue
		}
		if asn, ok := mmdbUint(value); ok && asn > 0 && asn <= math.MaxInt32 {
			return int(asn), key
		}
		text := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(mmdbText(value))), "AS")
		if text == "" {
			continue
		}
		asn, err := strconv.ParseUint(text, 10, 32)
		if err == nil && asn > 0 && asn <= math.MaxInt32 {
			return int(asn), key
		}
	}
	return 0, ""
}

// mmdbTextFrom returns the first non-empty string field and its key.
func mmdbTextFrom(record map[string]any, keys ...string) (string, string) {
	for _, key := range keys {
		if text := mmdbText(record[key]); text != "" {
			return text, key
		}
	}
	return "", ""
}

// mmdbNameFromObject extracts an English (or first available) localized name
// from a MaxMind "names" object, falling back to a top-level "name" field.
func mmdbNameFromObject(object map[string]any) (string, string) {
	if names := mmdbMap(object["names"]); names != nil {
		if name := mmdbText(names["en"]); name != "" {
			return name, "names.en"
		}
		keys := make([]string, 0, len(names))
		for key := range names {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if name := mmdbText(names[key]); name != "" {
				return name, "names." + key
			}
		}
	}
	if name := mmdbText(object["name"]); name != "" {
		return name, "name"
	}
	return "", ""
}

func mmdbMap(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func mmdbText(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func mmdbUint(value any) (uint64, bool) {
	switch number := value.(type) {
	case uint:
		return uint64(number), true
	case uint8:
		return uint64(number), true
	case uint16:
		return uint64(number), true
	case uint32:
		return uint64(number), true
	case uint64:
		return number, true
	case int:
		if number >= 0 {
			return uint64(number), true
		}
	case int8:
		if number >= 0 {
			return uint64(number), true
		}
	case int16:
		if number >= 0 {
			return uint64(number), true
		}
	case int32:
		if number >= 0 {
			return uint64(number), true
		}
	case int64:
		if number >= 0 {
			return uint64(number), true
		}
	case float64:
		if number >= 0 && number <= math.MaxUint32 && number == math.Trunc(number) {
			return uint64(number), true
		}
	}
	return 0, false
}

func mmdbCountryCode(raw string) string {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

// statusSnapshot returns the panel-visible state of the MMDB layer.
func (m *mmdbLayer) statusSnapshot() (enabled, healthy bool, failures int, lastErr string) {
	if m == nil {
		return false, false, 0, "mmdb layer is not configured"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lastErr = ""
	if m.loadErr != nil {
		lastErr = m.loadErr.Error()
	}
	return m.enabled, m.reader != nil || m.testLookup != nil, 0, lastErr
}

// setEnabled applies an operator decision to the local MMDB layer. Enabling
// retries loading a previously missing/corrupt file so an operator can drop in a
// fresh database and re-enable the layer without a restart. File I/O happens
// outside the layer lock.
func (m *mmdbLayer) setEnabled(enabled bool) error {
	if m == nil {
		return errors.New("geo: mmdb layer is not configured")
	}
	m.mu.Lock()
	if !enabled {
		m.enabled = false
		m.mu.Unlock()
		return nil
	}
	m.enabled = true
	needLoad := m.reader == nil && m.testLookup == nil && m.path != ""
	path := m.path
	m.mu.Unlock()
	if !needLoad {
		return nil
	}
	reader, err := maxminddb.Open(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.loadErr = fmt.Errorf("open %s: %w", path, err)
		return nil
	}
	if m.reader != nil {
		_ = m.reader.Close()
	}
	m.reader = reader
	m.loadErr = nil
	return nil
}

// close releases the open database handle. It is idempotent.
func (m *mmdbLayer) close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader == nil {
		return nil
	}
	err := m.reader.Close()
	m.reader = nil
	return err
}

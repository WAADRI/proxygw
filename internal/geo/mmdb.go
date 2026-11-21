package geo

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"proxygw/internal/model"
)

// mmdbRecord is the subset of the MaxMind GeoLite2 City/Country/ASN record used
// by this package. Missing fields are simply left zero; the MMDB layer is the
// primary source and online providers may fill the gaps.
type mmdbRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		Name    string `maxminddb:"name"`
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
	City struct {
		Name string `maxminddb:"name"`
	} `maxminddb:"city"`
	ASN    uint   `maxminddb:"autonomous_system_number"`
	ASNOrg string `maxminddb:"autonomous_system_organization"`
	ISP    string `maxminddb:"isp"`
}

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
	var record mmdbRecord
	if err := reader.Lookup(ip, &record); err != nil {
		return model.Geo{}, nil, fmt.Errorf("mmdb lookup %s: %w", ip, err)
	}
	return geoFromMMDBRecord(record)
}

// geoFromMMDBRecord maps a decoded MMDB record to the normalized Geo model.
func geoFromMMDBRecord(record mmdbRecord) (model.Geo, map[string]string, error) {
	geo := model.Geo{}
	hitPaths := map[string]string{}
	country := record.Country.ISOCode
	if country == "" {
		country = record.RegisteredCountry.ISOCode
	}
	if country != "" {
		geo.Country = country
		hitPaths[geoFieldCountry] = "country.iso_code"
	}
	if len(record.Subdivisions) > 0 {
		subdivision := record.Subdivisions[0]
		region := subdivision.Name
		if region == "" {
			region = subdivision.ISOCode
		}
		if region != "" {
			geo.Region = region
			hitPaths[geoFieldRegion] = "subdivisions[0].name"
		}
	}
	if record.City.Name != "" {
		geo.City = record.City.Name
		hitPaths[geoFieldCity] = "city.name"
	}
	if record.ASN > 0 && record.ASN <= math.MaxInt32 {
		geo.ASN = int(record.ASN)
		hitPaths[geoFieldASN] = "autonomous_system_number"
	}
	if record.ASNOrg != "" {
		geo.ASNOrg = record.ASNOrg
		hitPaths[geoFieldASNOrg] = "autonomous_system_organization"
	}
	if record.ISP != "" {
		geo.ISP = record.ISP
		hitPaths[geoFieldISP] = "isp"
	}
	return normalizeGeoFields(geo), hitPaths, nil
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

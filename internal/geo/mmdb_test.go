package geo

import "testing"

func TestGeoFromMMDBMapMaxMindLayout(t *testing.T) {
	record := map[string]any{
		"country": map[string]any{
			"iso_code": "US",
			"names":    map[string]any{"en": "United States"},
		},
		"subdivisions": []any{
			map[string]any{"iso_code": "CA", "names": map[string]any{"en": "California"}},
		},
		"city":                           map[string]any{"names": map[string]any{"en": "Mountain View"}},
		"autonomous_system_number":       uint64(15169),
		"autonomous_system_organization": "Google LLC",
		"isp":                            "Google LLC",
	}
	geo, hits, err := geoFromMMDBMap(record)
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" || geo.ISP != "Google LLC" {
		t.Fatalf("unexpected ASN/ISP: %+v", geo)
	}
	wantPaths := map[string]string{
		geoFieldCountry: "country.iso_code",
		geoFieldRegion:  "subdivisions[0].names.en",
		geoFieldCity:    "city.names.en",
		geoFieldASN:     "autonomous_system_number",
		geoFieldASNOrg:  "autonomous_system_organization",
		geoFieldISP:     "isp",
	}
	for field, want := range wantPaths {
		if hits[field] != want {
			t.Fatalf("%s hit path = %q, want %q (all: %+v)", field, hits[field], want, hits)
		}
	}
}

func TestGeoFromMMDBMapIPLocateLayout(t *testing.T) {
	// IPLocate's free country database stores the country name in "country"
	// and the ISO code in "country_code"; the old struct decoder failed with
	// "cannot unmarshal United States (string) into struct { ISOCode ... }".
	record := map[string]any{
		"country":        "United States",
		"country_code":   "US",
		"continent_code": "NA",
	}
	geo, hits, err := geoFromMMDBMap(record)
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.Country != "US" {
		t.Fatalf("Country = %q, want US", geo.Country)
	}
	if hits[geoFieldCountry] != "country_code" {
		t.Fatalf("country hit path = %q, want country_code", hits[geoFieldCountry])
	}
	if geo.Region != "" || geo.City != "" || geo.ASN != 0 {
		t.Fatalf("unexpected fields for country-only record: %+v", geo)
	}
}

func TestGeoFromMMDBMapFlatLayout(t *testing.T) {
	record := map[string]any{
		"country": "DE",
		"region":  "Bavaria",
		"city":    "Munich",
		"asn":     "AS3320",
		"as_name": "Deutsche Telekom AG",
		"isp":     "Deutsche Telekom",
	}
	geo, hits, err := geoFromMMDBMap(record)
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.Country != "DE" || geo.Region != "Bavaria" || geo.City != "Munich" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if geo.ASN != 3320 || geo.ASNOrg != "Deutsche Telekom AG" || geo.ISP != "Deutsche Telekom" {
		t.Fatalf("unexpected ASN/ISP: %+v", geo)
	}
	if hits[geoFieldCountry] != "country" || hits[geoFieldRegion] != "region" ||
		hits[geoFieldCity] != "city" || hits[geoFieldASN] != "asn" ||
		hits[geoFieldASNOrg] != "as_name" {
		t.Fatalf("unexpected hit paths: %+v", hits)
	}
}

func TestGeoFromMMDBMapCountryNameOnly(t *testing.T) {
	geo, _, err := geoFromMMDBMap(map[string]any{"country": "United States"})
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.Country != "" {
		t.Fatalf("full country name must not be treated as ISO code: %+v", geo)
	}
}

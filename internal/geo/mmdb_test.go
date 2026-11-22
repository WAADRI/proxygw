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
	geo, hits, err := geoFromMMDBMap(record, "en")
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
	geo, hits, err := geoFromMMDBMap(record, "en")
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
	geo, hits, err := geoFromMMDBMap(record, "en")
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
	geo, _, err := geoFromMMDBMap(map[string]any{"country": "United States"}, "en")
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.Country != "" {
		t.Fatalf("full country name must not be treated as ISO code: %+v", geo)
	}
}

func TestGeoFromMMDBMapLocalizedNames(t *testing.T) {
	record := map[string]any{
		"country": map[string]any{"iso_code": "CN"},
		"city": map[string]any{"names": map[string]any{
			"en":    "Nanjing",
			"zh-CN": "南京",
		}},
		"subdivisions": []any{
			map[string]any{"names": map[string]any{
				"en":    "Jiangsu",
				"zh-CN": "江苏",
			}},
		},
	}

	geo, hits, err := geoFromMMDBMap(record, "zh-CN")
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.City != "南京" || geo.Region != "江苏" {
		t.Fatalf("localized geo = %+v, want 南京/江苏", geo)
	}
	if hits[geoFieldCity] != "city.names.zh-CN" || hits[geoFieldRegion] != "subdivisions[0].names.zh-CN" {
		t.Fatalf("unexpected localized hit paths: %+v", hits)
	}

	// Requesting a missing language must fall back to English.
	geo, hits, err = geoFromMMDBMap(record, "ja")
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.City != "Nanjing" || geo.Region != "Jiangsu" {
		t.Fatalf("fallback geo = %+v, want English fallback", geo)
	}
	if hits[geoFieldCity] != "city.names.en" {
		t.Fatalf("fallback city path = %q, want city.names.en", hits[geoFieldCity])
	}
}

func TestGeoFromMMDBMapNestedASN(t *testing.T) {
	record := map[string]any{
		"asn": map[string]any{
			"autonomous_system_number":       uint64(15169),
			"autonomous_system_organization": "Google LLC",
			"as_domain":                      "google.com",
		},
	}
	geo, hits, err := geoFromMMDBMap(record, "en")
	if err != nil {
		t.Fatalf("geoFromMMDBMap: %v", err)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("nested ASN geo = %+v, want AS15169/Google LLC", geo)
	}
	if hits[geoFieldASN] != "asn.autonomous_system_number" {
		t.Fatalf("ASN path = %q", hits[geoFieldASN])
	}
	if hits[geoFieldASNOrg] != "asn.autonomous_system_organization" {
		t.Fatalf("ASN org path = %q", hits[geoFieldASNOrg])
	}
}

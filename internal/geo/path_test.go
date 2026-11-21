package geo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"proxygw/internal/model"
)

func decodeJSONDoc(t *testing.T, raw string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode test doc: %v", err)
	}
	return doc
}

func TestLookupJSONPath(t *testing.T) {
	doc := decodeJSONDoc(t, `{
		"data": {"country": "JP", "list": [{"x": 1}, {"x": 2}]},
		"items": [10, 20]
	}`)
	okCases := []struct {
		path string
		want any
	}{
		{"$.data.country", "JP"},
		{"$.data.list[1].x", float64(2)},
		{"$.items[0]", float64(10)},
		{"data.country", "JP"},
		{"$", doc},
	}
	for _, tc := range okCases {
		got, err := LookupJSONPath(doc, tc.path)
		if err != nil {
			t.Fatalf("LookupJSONPath(%q): %v", tc.path, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("LookupJSONPath(%q) = %#v, want %#v", tc.path, got, tc.want)
		}
	}

	errCases := []struct {
		name string
		doc  any
		path string
		want string
	}{
		{"missing key", doc, "$.data.nope", `key "nope" not found`},
		{"index out of range", doc, "$.items[5]", "out of range"},
		{"index on object", doc, "$.data.country[0]", "expected an array"},
		{"key on array", doc, "$.items.country", "expected an object"},
		{"unterminated index", doc, "$.items[0", "unterminated array index"},
		{"invalid index", doc, "$.items[x]", "invalid array index"},
		{"negative index", doc, "$.items[-1]", "invalid array index"},
		{"empty key", doc, "$.data..country", "empty object key"},
		{"invalid segment", doc, "$data", "unexpected"},
		{"empty path", doc, "", "empty path"},
		{"root is scalar", "hello", "$.a", "expected an object"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LookupJSONPath(tc.doc, tc.path)
			if err == nil {
				t.Fatalf("LookupJSONPath(%q) unexpectedly succeeded", tc.path)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), tc.path) && tc.path != "" {
				t.Fatalf("error %q should name the path", err.Error())
			}
		})
	}
}

func TestApplyTemplateFields(t *testing.T) {
	t.Run("nested json paths", func(t *testing.T) {
		body := []byte(`{"data":{"country":"JP","asn":"AS2516"}}`)
		geo, hitPaths, err := ApplyTemplateFields(body, map[string]string{
			"country": "data.country",
			"asn":     "data.asn",
		})
		if err != nil {
			t.Fatalf("ApplyTemplateFields: %v", err)
		}
		if geo.Country != "JP" {
			t.Fatalf("Country = %q, want JP", geo.Country)
		}
		if geo.ASN != 2516 {
			t.Fatalf("ASN = %d, want 2516", geo.ASN)
		}
		if hitPaths["country"] != "data.country" || hitPaths["asn"] != "data.asn" {
			t.Fatalf("unexpected hit paths: %+v", hitPaths)
		}
	})

	t.Run("regex plain text", func(t *testing.T) {
		body := []byte("country=JP\nasn=AS2516\n")
		geo, hitPaths, err := ApplyTemplateFields(body, map[string]string{
			"country": `regex:country=([A-Z]{2})`,
			"asn":     `regex:asn=(AS[0-9]+)`,
		})
		if err != nil {
			t.Fatalf("ApplyTemplateFields: %v", err)
		}
		if geo.Country != "JP" || geo.ASN != 2516 {
			t.Fatalf("unexpected geo: %+v", geo)
		}
		if hitPaths["country"] != `regex:country=([A-Z]{2})` {
			t.Fatalf("unexpected hit paths: %+v", hitPaths)
		}
	})

	t.Run("array index", func(t *testing.T) {
		body := []byte(`{"results":[{"country":"DE"}]}`)
		geo, _, err := ApplyTemplateFields(body, map[string]string{"country": "$.results[0].country"})
		if err != nil {
			t.Fatalf("ApplyTemplateFields: %v", err)
		}
		if geo.Country != "DE" {
			t.Fatalf("Country = %q, want DE", geo.Country)
		}
	})

	t.Run("missing path is an error", func(t *testing.T) {
		body := []byte(`{"data":{"country":"JP"}}`)
		_, _, err := ApplyTemplateFields(body, map[string]string{"country": "$.data.nope"})
		if err == nil {
			t.Fatal("missing path must be a hard error")
		}
		for _, want := range []string{"country", "$.data.nope", "not found"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain %q", err.Error(), want)
			}
		}
	})

	t.Run("type mismatch is an error", func(t *testing.T) {
		body := []byte(`{"country":42}`)
		_, _, err := ApplyTemplateFields(body, map[string]string{"country": "$.country"})
		if err == nil || !strings.Contains(err.Error(), "expected a string") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty value is an error", func(t *testing.T) {
		body := []byte(`{"country":""}`)
		_, _, err := ApplyTemplateFields(body, map[string]string{"country": "$.country"})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("regex mismatch is an error", func(t *testing.T) {
		_, _, err := ApplyTemplateFields([]byte("nope"), map[string]string{"country": `regex:country=([A-Z]{2})`})
		if err == nil || !strings.Contains(err.Error(), "did not match") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid regex is an error", func(t *testing.T) {
		_, _, err := ApplyTemplateFields([]byte("x"), map[string]string{"country": "regex:("})
		if err == nil || !strings.Contains(err.Error(), "invalid regex") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("json mapping on non json body", func(t *testing.T) {
		_, _, err := ApplyTemplateFields([]byte("plain text"), map[string]string{"country": "$.country"})
		if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unsupported field", func(t *testing.T) {
		_, _, err := ApplyTemplateFields([]byte(`{}`), map[string]string{"continent": "$.continent"})
		if err == nil || !strings.Contains(err.Error(), "unsupported field") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no mappings", func(t *testing.T) {
		_, _, err := ApplyTemplateFields([]byte(`{}`), nil)
		if err == nil {
			t.Fatal("expected an error for no mappings")
		}
	})
}

func TestParseSchema(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		geo, err := ParseSchema([]byte(`{"country":"jp","region":"Tokyo","city":"Tokyo","asn":2516,"asn_org":"KDDI","isp":"KDDI"}`))
		if err != nil {
			t.Fatalf("ParseSchema: %v", err)
		}
		if geo.Country != "JP" || geo.Region != "Tokyo" || geo.City != "Tokyo" || geo.ASN != 2516 || geo.ASNOrg != "KDDI" || geo.ISP != "KDDI" {
			t.Fatalf("unexpected geo: %+v", geo)
		}
	})

	t.Run("partial", func(t *testing.T) {
		geo, err := ParseSchema([]byte(`{"country":"US"}`))
		if err != nil {
			t.Fatalf("ParseSchema: %v", err)
		}
		if geo.Country != "US" || geo.ASN != 0 || geo.ISP != "" {
			t.Fatalf("unexpected geo: %+v", geo)
		}
	})

	t.Run("asn string", func(t *testing.T) {
		geo, err := ParseSchema([]byte(`{"asn":"AS15169"}`))
		if err != nil {
			t.Fatalf("ParseSchema: %v", err)
		}
		if geo.ASN != 15169 {
			t.Fatalf("ASN = %d, want 15169", geo.ASN)
		}
	})

	t.Run("empty object", func(t *testing.T) {
		geo, err := ParseSchema([]byte(`{}`))
		if err != nil {
			t.Fatalf("ParseSchema: %v", err)
		}
		if !geo.IsZero() {
			t.Fatalf("expected zero geo, got %+v", geo)
		}
	})

	t.Run("null fields treated as absent", func(t *testing.T) {
		geo, err := ParseSchema([]byte(`{"country":null,"asn":null}`))
		if err != nil {
			t.Fatalf("ParseSchema: %v", err)
		}
		if !geo.IsZero() {
			t.Fatalf("expected zero geo, got %+v", geo)
		}
	})

	errCases := []struct {
		name string
		body string
		want string
	}{
		{"bad json", `{"country":`, "not a valid JSON object"},
		{"wrong country type", `{"country":123}`, "expected a string"},
		{"wrong asn type", `{"asn":true}`, `expected an integer`},
		{"fractional asn", `{"asn":2516.5}`, "expected"},
		{"negative asn", `{"asn":-5}`, "positive"},
		{"trailing data", `{"country":"US"} {"x":1}`, "trailing"},
		{"array root", `[{"country":"US"}]`, "not a valid JSON object"},
		{"null root", `null`, "must be a JSON object"},
		{"empty body", "", "empty response body"},
		{"invalid country code", `{"country":"USA"}`, "two-letter"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSchema([]byte(tc.body))
			if err == nil {
				t.Fatalf("ParseSchema(%q) unexpectedly succeeded", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestNormalizeGeo(t *testing.T) {
	geo := NormalizeGeo(model.Geo{Country: " us ", Region: " California ", City: "  ", ASN: -1}, "custom")
	if geo.Country != "US" {
		t.Fatalf("Country = %q, want US", geo.Country)
	}
	if geo.Region != "California" {
		t.Fatalf("Region = %q, want trimmed", geo.Region)
	}
	if geo.City != "" {
		t.Fatalf("City = %q, want empty", geo.City)
	}
	if geo.ASN != 0 {
		t.Fatalf("ASN = %d, want 0", geo.ASN)
	}
	if geo.Provider != "custom" {
		t.Fatalf("Provider = %q, want custom", geo.Provider)
	}
	if geo.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must be set for non-zero geo")
	}

	zero := NormalizeGeo(model.Geo{}, "custom")
	if !zero.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must stay zero for empty geo")
	}
}

func TestNormalizeCountryASNBoundaries(t *testing.T) {
	if got := model.NormalizeCountry(" jp "); got != "JP" {
		t.Fatalf("NormalizeCountry = %q, want JP", got)
	}
	if got := model.NormalizeCountry(""); got != "" {
		t.Fatalf("NormalizeCountry(empty) = %q", got)
	}
	if got := model.NormalizeCountry("usa"); got != "USA" {
		t.Fatalf("NormalizeCountry(usa) = %q", got)
	}

	asnCases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"AS15169", 15169, false},
		{"as15169", 15169, false},
		{"As15169", 15169, false},
		{"15169", 15169, false},
		{" AS15169 ", 15169, false},
		{"", 0, true},
		{"AS0", 0, true},
		{"AS-1", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range asnCases {
		got, err := model.NormalizeASN(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeASN(%q) unexpectedly succeeded", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeASN(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeASN(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	if got := normalizeGeoFields(model.Geo{Country: "de", ASNOrg: " org "}); got.Country != "DE" || got.ASNOrg != "org" {
		t.Fatalf("normalizeGeoFields = %+v", got)
	}
}

func TestSplitASNOrg(t *testing.T) {
	cases := []struct {
		in      string
		wantASN int
		wantOrg string
	}{
		{"AS15169 Google LLC", 15169, "Google LLC"},
		{"AS15169", 15169, ""},
		{"15169 Google LLC", 15169, "Google LLC"},
		{"Google LLC", 0, "Google LLC"},
		{"", 0, ""},
	}
	for _, tc := range cases {
		asn, org := splitASNOrg(tc.in)
		if asn != tc.wantASN || org != tc.wantOrg {
			t.Fatalf("splitASNOrg(%q) = (%d, %q), want (%d, %q)", tc.in, asn, org, tc.wantASN, tc.wantOrg)
		}
	}
}

func TestValidateGeoFields(t *testing.T) {
	if err := validateGeoFields(model.Geo{Country: "JP"}); err != nil {
		t.Fatalf("validateGeoFields: %v", err)
	}
	for _, country := range []string{"USA", "J", "J1", "jp"} {
		if err := validateGeoFields(model.Geo{Country: country}); err == nil {
			t.Fatalf("validateGeoFields(%q) unexpectedly succeeded", country)
		}
	}
	if err := validateGeoFields(model.Geo{ASN: -3}); err == nil {
		t.Fatal("negative ASN must be rejected")
	}
}

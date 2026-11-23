package geo

import (
	"net"
	"net/url"
	"strings"
	"testing"

	"proxygw/internal/config"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return parsed
}

func TestParseIPInfoBody(t *testing.T) {
	body := []byte(`{"ip":"8.8.8.8","country":"US","region":"California","city":"Mountain View","org":"AS15169 Google LLC"}`)
	geo, hits, err := parseIPInfoBody(body)
	if err != nil {
		t.Fatalf("parseIPInfoBody: %v", err)
	}
	geo = normalizeGeoFields(geo)
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("unexpected ASN split: %+v", geo)
	}
	if hits[geoFieldASN] != "org" || hits[geoFieldASNOrg] != "org" {
		t.Fatalf("unexpected hit paths: %+v", hits)
	}

	errorCases := []struct {
		name string
		body string
		want string
	}{
		{"api error", `{"error":{"title":"Wrong ip","message":"Invalid IP"}}`, "API error"},
		{"bogon", `{"ip":"10.0.0.1","bogon":true}`, "bogon"},
		{"unexpected format", `{"foo":"bar"}`, "did not contain any known field"},
		{"bad json", `not json`, "not valid JSON"},
		{"invalid country", `{"country":"USA"}`, "two-letter"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseIPInfoBody([]byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseIPInfoLiteBody(t *testing.T) {
	body := []byte(`{"ip":"8.8.8.8","asn":"AS15169","as_name":"Google LLC","as_domain":"google.com","country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}`)
	geo, hits, err := parseIPInfoBody(body)
	if err != nil {
		t.Fatalf("parseIPInfoLiteBody: %v", err)
	}
	if geo.Country != "US" || geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("unexpected lite geo: %+v", geo)
	}
	if hits[geoFieldCountry] != "country_code" || hits[geoFieldASN] != "asn" {
		t.Fatalf("unexpected lite hit paths: %+v", hits)
	}
}

func TestParseIPInfoCoreBody(t *testing.T) {
	body := []byte(`{
		"ip":"8.8.8.8",
		"geo":{"city":"Mountain View","region":"California","region_code":"CA","country":"United States","country_code":"US"},
		"as":{"asn":"AS15169","name":"Google LLC","domain":"google.com"}
	}`)
	geo, _, err := parseIPInfoBody(body)
	if err != nil {
		t.Fatalf("parseIPInfoCoreBody: %v", err)
	}
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" || geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("unexpected core geo: %+v", geo)
	}
}

func TestParseIPInfoLegacyBody(t *testing.T) {
	body := []byte(`{"ip":"8.8.8.8","city":"Mountain View","region":"California","country":"US","org":"AS15169 Google LLC"}`)
	geo, _, err := parseIPInfoBody(body)
	if err != nil {
		t.Fatalf("parseIPInfoLegacyBody: %v", err)
	}
	if geo.Country != "US" || geo.City != "Mountain View" || geo.ASN != 15169 {
		t.Fatalf("unexpected legacy geo: %+v", geo)
	}
}

func TestParseIPAPIBody(t *testing.T) {
	body := []byte(`{"status":"success","countryCode":"US","regionName":"California","city":"Mountain View","as":"AS15169 Google LLC","isp":"Google LLC","query":"8.8.8.8"}`)
	geo, hits, err := parseIPAPIBody(body)
	if err != nil {
		t.Fatalf("parseIPAPIBody: %v", err)
	}
	geo = normalizeGeoFields(geo)
	if geo.Country != "US" || geo.Region != "California" || geo.City != "Mountain View" || geo.ISP != "Google LLC" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if geo.ASN != 15169 || geo.ASNOrg != "Google LLC" {
		t.Fatalf("unexpected ASN: %+v", geo)
	}
	if hits[geoFieldCountry] != "countryCode" || hits[geoFieldISP] != "isp" {
		t.Fatalf("unexpected hit paths: %+v", hits)
	}

	if _, _, err := parseIPAPIBody([]byte(`{"status":"fail","message":"private range"}`)); err == nil ||
		!strings.Contains(err.Error(), "fail") || !strings.Contains(err.Error(), "private range") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := parseIPAPIBody([]byte(`{"countryCode":"US"}`)); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := parseIPAPIBody([]byte(`not json`)); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseIPWhoisBody(t *testing.T) {
	body := []byte(`{"success":true,"country_code":"JP","region":"Tokyo","city":"Tokyo","connection":{"asn":2516,"org":"KDDI","isp":"KDDI"}}`)
	geo, hits, err := parseIPWhoisBody(body)
	if err != nil {
		t.Fatalf("parseIPWhoisBody: %v", err)
	}
	geo = normalizeGeoFields(geo)
	if geo.Country != "JP" || geo.Region != "Tokyo" || geo.ASN != 2516 || geo.ASNOrg != "KDDI" || geo.ISP != "KDDI" {
		t.Fatalf("unexpected geo: %+v", geo)
	}
	if hits[geoFieldCountry] != "country_code" || hits[geoFieldASN] != "connection.asn" {
		t.Fatalf("unexpected hit paths: %+v", hits)
	}

	if _, _, err := parseIPWhoisBody([]byte(`{"success":false,"message":"invalid IP address"}`)); err == nil ||
		!strings.Contains(err.Error(), "invalid IP address") {
		t.Fatalf("unexpected error: %v", err)
	}

	geo, _, err = parseIPWhoisBody([]byte(`{"success":true,"country_code":"US","connection":{"asn":"AS15169","org":"Google LLC"}}`))
	if err != nil {
		t.Fatalf("parseIPWhoisBody with string ASN: %v", err)
	}
	if geo.ASN != 15169 {
		t.Fatalf("ASN = %d, want 15169", geo.ASN)
	}
}

func TestParseCloudflareTrace(t *testing.T) {
	geo, hits, err := parseCloudflareTrace([]byte("fl=abcdef\nip=8.8.8.8\nloc=jp\ntls=TLSv1.3\n"))
	if err != nil {
		t.Fatalf("parseCloudflareTrace: %v", err)
	}
	if geo.Country != "JP" {
		t.Fatalf("Country = %q, want JP", geo.Country)
	}
	if hits[geoFieldCountry] != "loc" {
		t.Fatalf("unexpected hit paths: %+v", hits)
	}
	if _, _, err := parseCloudflareTrace([]byte("fl=abcdef\nip=8.8.8.8\n")); err == nil || !strings.Contains(err.Error(), "loc") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildProviderTargetURL(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")

	newProvider := func(kind providerKind, preset, rawURL, token string) *provider {
		return &provider{
			kind:   kind,
			preset: preset,
			cfg:    config.ProviderConfig{URL: rawURL, Token: token},
		}
	}

	t.Run("ipinfo default", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPInfo, "", ""), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://api.ipinfo.io/lite/8.8.8.8" {
			t.Fatalf("URL = %q", got)
		}
	})

	t.Run("ipinfo new api without placeholder appends path", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPInfo, "https://api.ipinfo.io/lite", ""), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://api.ipinfo.io/lite/8.8.8.8" {
			t.Fatalf("URL = %q", got)
		}
	})

	t.Run("ipinfo legacy host without placeholder appends /json", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPInfo, "https://ipinfo.io", ""), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://ipinfo.io/8.8.8.8/json" {
			t.Fatalf("URL = %q", got)
		}
	})

	t.Run("ipinfo token in query", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPInfo, "https://ipinfo.io/{ip}/json", "secret-token"), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		parsed := mustParseURL(t, got)
		if parsed.Query().Get("token") != "secret-token" {
			t.Fatalf("token query missing: %q", got)
		}
		if parsed.Path != "/8.8.8.8/json" {
			t.Fatalf("path = %q", parsed.Path)
		}
	})

	t.Run("ip-api default fields and key", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPAPI, "", "api-key"), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		parsed := mustParseURL(t, got)
		if parsed.Host != "ip-api.com" || parsed.Path != "/json/8.8.8.8" {
			t.Fatalf("unexpected URL parts: %+v", parsed)
		}
		query := parsed.Query()
		if query.Get("key") != "api-key" {
			t.Fatalf("key query missing: %q", got)
		}
		if !strings.Contains(query.Get("fields"), "countryCode") {
			t.Fatalf("fields query missing: %q", got)
		}
	})

	t.Run("ip-api custom URL appends ip", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPAPI, "https://proxy.example/lookup", ""), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://proxy.example/lookup/8.8.8.8" {
			t.Fatalf("URL = %q", got)
		}
	})

	t.Run("cloudflare default", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetCloudflare, "", ""), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://cloudflare.com/cdn-cgi/trace" {
			t.Fatalf("URL = %q", got)
		}
	})

	t.Run("template ip and token placeholders", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindTemplate, "", "https://example.com/lookup?ip={ip}", "tok"), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		parsed := mustParseURL(t, got)
		query := parsed.Query()
		if query.Get("ip") != "8.8.8.8" || query.Get("token") != "tok" {
			t.Fatalf("unexpected query: %q", got)
		}
	})

	t.Run("existing token query preserved", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindTemplate, "", "https://example.com/lookup?token=already", "new"), ip)
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		parsed := mustParseURL(t, got)
		if parsed.Query().Get("token") != "already" {
			t.Fatalf("existing token must not be overwritten: %q", got)
		}
	})

	t.Run("ipv6 substitution", func(t *testing.T) {
		got, err := buildProviderTargetURL(newProvider(providerKindPreset, presetIPWhois, "", ""), net.ParseIP("2001:db8::1"))
		if err != nil {
			t.Fatalf("buildProviderTargetURL: %v", err)
		}
		if got != "https://ipwho.is/2001:db8::1" {
			t.Fatalf("URL = %q", got)
		}
	})
}

func TestProviderConfigValidation(t *testing.T) {
	base := testGeoConfig()
	cases := []struct {
		name     string
		provider config.ProviderConfig
		want     string
	}{
		{
			name:     "unknown preset",
			provider: config.ProviderConfig{Name: "p", Type: "preset", Preset: "nope", URL: "https://example.com", Enabled: true},
			want:     "unknown preset",
		},
		{
			name:     "template without fields",
			provider: config.ProviderConfig{Name: "p", Type: "template", URL: "https://example.com", Enabled: true},
			want:     "at least one field mapping",
		},
		{
			name:     "template bad field",
			provider: config.ProviderConfig{Name: "p", Type: "template", URL: "https://example.com", Enabled: true, Fields: map[string]string{"continent": "$.continent"}},
			want:     "unsupported field",
		},
		{
			name:     "template bad regex",
			provider: config.ProviderConfig{Name: "p", Type: "template", URL: "https://example.com", Enabled: true, Fields: map[string]string{"country": "regex:("}},
			want:     "invalid regex",
		},
		{
			name:     "schema without URL",
			provider: config.ProviderConfig{Name: "p", Type: "schema", Enabled: true},
			want:     "requires a URL",
		},
		{
			name:     "http URL in production",
			provider: config.ProviderConfig{Name: "p", Type: "schema", URL: "http://example.com/x", Enabled: true},
			want:     "only https",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Providers = []config.ProviderConfig{tc.provider}
			_, err := New(Options{Config: cfg, Logger: testLogger()})
			if err == nil {
				t.Fatalf("New unexpectedly succeeded for %+v", tc.provider)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

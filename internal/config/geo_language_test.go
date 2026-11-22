package config

import "testing"

func TestGeoMMDBNameLanguageValidation(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Geo.MMDBNameLanguage = "zh-CN"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with zh-CN: %v", err)
	}
	if cfg.Geo.MMDBNameLanguage != "zh-CN" {
		t.Fatalf("MMDBNameLanguage = %q", cfg.Geo.MMDBNameLanguage)
	}

	cfg = DefaultServerConfig()
	cfg.Geo.MMDBNameLanguage = "zh CN"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted an invalid language tag")
	}

	cfg = DefaultServerConfig()
	cfg.Geo.MMDBNameLanguage = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with empty language: %v", err)
	}
}

package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthOK(t *testing.T) {
	s := New()
	s.AddCheck("config", func() error { return nil })
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.OK || st.Checks["config"] != "ok" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestHealthFailingCheck(t *testing.T) {
	s := New()
	s.AddCheck("storage", func() error { return errors.New("disk full") })
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.OK {
		t.Fatalf("expected not ok: %+v", st)
	}
}

func TestVersionHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	VersionHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var v map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v["go_version"]; !ok {
		t.Fatalf("missing go_version: %+v", v)
	}
}

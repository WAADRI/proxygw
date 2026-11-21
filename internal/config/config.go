// Package config implements the three-layer configuration model required by
// the specification: environment variables > config file > built-in defaults.
// It also performs full startup validation with field-accurate error messages.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"proxygw/internal/logx"
	"proxygw/internal/model"
)

// EnvPrefix is the environment variable prefix for the server binary.
const EnvPrefix = "NP_"

// Common weak/example secrets that must never silently reach production.
var weakSecrets = map[string]bool{
	"": true, "password": true, "passwd": true, "admin": true, "123456": true,
	"12345678": true, "changeme": true, "change-me": true, "secret": true,
	"token": true, "test": true, "example": true, "demo": true, "default": true,
	"proxygw": true, "letmein": true, "qwerty": true,
}

// IsWeakSecret reports whether s looks like a placeholder/example secret.
func IsWeakSecret(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	if weakSecrets[v] {
		return true
	}
	if len(v) < 16 {
		return true
	}
	return false
}

// CheckWeakSecrets returns an error naming all weak secret fields unless
// allowInsecureDefaults is explicitly enabled.
func CheckWeakSecrets(allowInsecureDefaults bool, fields map[string]string) error {
	var problems []string
	for name, value := range fields {
		if value == "" {
			continue // unset is handled by other validation / runtime generation
		}
		if IsWeakSecret(value) {
			problems = append(problems, name)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sortStrings(problems)
	if allowInsecureDefaults {
		return nil
	}
	return fmt.Errorf("security: weak/example secret detected in %s; set strong random values or explicitly set security.allow_insecure_defaults=true for local development",
		strings.Join(problems, ", "))
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// readYAMLFile decodes path into out. Missing files are reported as
// os.ErrNotExist so callers can decide whether that is fatal.
func readYAMLFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// applyEnv walks the exported struct fields of cfg recursively and overrides
// values from environment variables. When a field carries an explicit
// `env:"NAME"` tag that name is used; otherwise, when prefix is non-empty, the
// name is derived from the dotted YAML path (e.g. proxy.http_listen ->
// NP_PROXY_HTTP_LISTEN).
func applyEnv(cfg any, prefix string) error {
	if cfg == nil {
		return nil
	}
	rv := reflect.ValueOf(cfg)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("applyEnv: expected non-nil pointer")
	}
	return walkEnv(rv.Elem(), "", prefix)
}

func walkEnv(v reflect.Value, path, prefix string) error {
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		fv := v.Field(i)
		name := f.Name
		if y := f.Tag.Get("yaml"); y != "" {
			if n := strings.Split(y, ",")[0]; n != "" && n != "-" {
				name = n
			}
		}
		childPath := name
		if path != "" {
			childPath = path + "." + name
		}
		// Recurse into structs and pointers to structs first so that nested
		// env override keeps working without special cases.
		if isStructLike(f.Type) {
			if err := walkEnvValue(fv, childPath, prefix); err != nil {
				return err
			}
			continue
		}
		envName := f.Tag.Get("env")
		if envName == "" && prefix != "" {
			envName = prefix + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(childPath))
		}
		if envName == "" {
			continue
		}
		raw, ok := os.LookupEnv(envName)
		if !ok {
			continue
		}
		if err := setFromString(fv, raw); err != nil {
			return fmt.Errorf("env %s: %w", envName, err)
		}
	}
	return nil
}

func walkEnvValue(fv reflect.Value, path, prefix string) error {
	switch fv.Kind() {
	case reflect.Struct:
		return walkEnv(fv, path, prefix)
	case reflect.Pointer:
		if fv.Type().Elem().Kind() != reflect.Struct {
			return nil
		}
		// Only allocate on demand: check whether any nested env var exists.
		if fv.IsNil() {
			before := countRelevantEnv(fv.Type().Elem(), path, prefix)
			if before == 0 {
				return nil
			}
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		return walkEnv(fv.Elem(), path, prefix)
	}
	return nil
}

// countRelevantEnv reports how many environment variables would apply to a
// struct type. It is used to decide whether an optional pointer struct should
// be allocated.
func countRelevantEnv(t reflect.Type, path, prefix string) int {
	n := 0
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name := f.Name
		if y := f.Tag.Get("yaml"); y != "" {
			if v := strings.Split(y, ",")[0]; v != "" && v != "-" {
				name = v
			}
		}
		childPath := name
		if path != "" {
			childPath = path + "." + name
		}
		if isStructLike(f.Type) {
			n += countRelevantEnv(baseStructType(f.Type), childPath, prefix)
			continue
		}
		envName := f.Tag.Get("env")
		if envName == "" && prefix != "" {
			envName = prefix + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(childPath))
		}
		if envName == "" {
			continue
		}
		if _, ok := os.LookupEnv(envName); ok {
			n++
		}
	}
	return n
}

func baseStructType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func isStructLike(t reflect.Type) bool {
	b := baseStructType(t)
	return b.Kind() == reflect.Struct
}

// setFromString assigns a raw environment string to a config field.
func setFromString(fv reflect.Value, raw string) error {
	if fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		return setFromString(fv.Elem(), raw)
	}
	// Prefer encoding.TextUnmarshaler (model.Duration, net.IP, etc.).
	if fv.CanAddr() {
		if tu, ok := fv.Addr().Interface().(interface{ UnmarshalText([]byte) error }); ok {
			if err := tu.UnmarshalText([]byte(raw)); err != nil {
				return err
			}
			return nil
		}
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid bool %q", raw)
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, fv.Type().Bits())
		if err != nil {
			return fmt.Errorf("invalid integer %q", raw)
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, fv.Type().Bits())
		if err != nil {
			return fmt.Errorf("invalid unsigned integer %q", raw)
		}
		fv.SetUint(n)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), fv.Type().Bits())
		if err != nil {
			return fmt.Errorf("invalid float %q", raw)
		}
		fv.SetFloat(f)
	case reflect.Slice:
		if fv.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice element type %s", fv.Type().Elem())
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		fv.Set(reflect.ValueOf(out))
	case reflect.Map:
		if fv.Type().Key().Kind() != reflect.String || fv.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported map type %s", fv.Type())
		}
		out := make(map[string]string)
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			k, val, ok := strings.Cut(pair, "=")
			if !ok {
				return fmt.Errorf("invalid map entry %q, want key=value", pair)
			}
			out[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
		fv.Set(reflect.ValueOf(out))
	default:
		return fmt.Errorf("unsupported kind %s", fv.Kind())
	}
	return nil
}

// ListenHostPort splits a listen address and validates the port range.
func ListenHostPort(addr string) (host string, port int, err error) {
	if strings.TrimSpace(addr) == "" {
		return "", 0, errors.New("empty listen address")
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	port, perr := strconv.Atoi(p)
	if perr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q in listen address %q (want 1-65535)", p, addr)
	}
	return h, port, nil
}

// IsLoopbackListen reports whether the listen host is loopback-only.
func IsLoopbackListen(addr string) bool {
	h, _, err := ListenHostPort(addr)
	if err != nil {
		return false
	}
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackHost reports whether host (no port) is loopback.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateLog validates a log configuration.
func ValidateLog(c logx.Config) error { return c.Validate() }

// AbsState returns the absolute state directory (or "" when dir is empty).
func AbsState(dir string) string {
	if dir == "" {
		return ""
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// StringsJoinNonEmpty joins non-empty strings with sep.
func StringsJoinNonEmpty(sep string, in ...string) string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}

// SettingsDefaults exposes model defaults for main wiring.
func SettingsDefaults() model.Settings { return model.DefaultSettings() }

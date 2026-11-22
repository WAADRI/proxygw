package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const maxPanelDomainLen = 253

var panelDomainLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizePanelDomain validates and canonicalizes the optional panel domain.
// The value must be a bare host name (an optional :port is accepted and
// dropped) and is stored lower-case without a trailing dot. An empty value
// disables the restriction.
func NormalizePanelDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "://") {
		return "", fmt.Errorf("must be a bare host name without a scheme")
	}
	if strings.ContainsAny(s, " \t\r\n/\\?#") {
		return "", fmt.Errorf("must be a bare host name without a path, query or spaces")
	}
	if strings.Contains(s, "*") {
		return "", fmt.Errorf("wildcards are not supported")
	}
	host := s
	if strings.Contains(s, ":") {
		h, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", fmt.Errorf("must be host or host:port: %w", err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port %q", port)
		}
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("must not be empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if len(host) > maxPanelDomainLen {
		return "", fmt.Errorf("host name is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if !panelDomainLabelRe.MatchString(label) {
			return "", fmt.Errorf("invalid host name %q", host)
		}
	}
	return host, nil
}

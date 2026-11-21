package proxy

import (
	"net"
	"strconv"
	"strings"
)

// maxTargetHostLen mirrors protocol.MaxDomainLen: longer names cannot be
// encoded into an OPEN header, so they are rejected at the entry point.
const maxTargetHostLen = 255

// validateTarget checks a target host / port pair parsed from an entry protocol
// request. Invalid targets are rejected locally with HTTP 400 / SOCKS5 general
// failure before any node is contacted.
func validateTarget(host string, port int) *proxyError {
	if host == "" {
		return errInvalidTarget("目标主机为空", nil)
	}
	if len(host) > maxTargetHostLen {
		return errInvalidTarget("目标主机名过长", nil)
	}
	if port < 1 || port > 65535 {
		return errInvalidTarget("目标端口非法", nil)
	}
	if strings.ContainsAny(host, " \t\r\n/\\?#@") {
		return errInvalidTarget("目标主机包含非法字符", nil)
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x20 || host[i] == 0x7f {
			return errInvalidTarget("目标主机包含控制字符", nil)
		}
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return errInvalidTarget("目标 IP 地址非法", nil)
	}
	return nil
}

// parsePort parses a decimal port in the range 1..65535.
func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, strconv.ErrRange
	}
	return port, nil
}

// splitAuthority parses "host:port", "[ipv6]:port", a bare IPv6 literal or a
// bare host name. defaultPort is used when the authority carries no port.
func splitAuthority(raw string, defaultPort int) (string, int, *proxyError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errInvalidTarget("目标地址为空", nil)
	}
	if strings.HasPrefix(raw, "[") || strings.Count(raw, ":") == 1 {
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, errInvalidTarget("目标地址格式非法，应为主机:端口", err)
		}
		port, err := parsePort(portStr)
		if err != nil {
			return "", 0, errInvalidTarget("目标端口非法", err)
		}
		return host, port, nil
	}
	if strings.Contains(raw, ":") {
		// Bare IPv6 literal without a port.
		if net.ParseIP(raw) == nil {
			return "", 0, errInvalidTarget("目标 IP 地址非法", nil)
		}
		return raw, defaultPort, nil
	}
	return raw, defaultPort, nil
}

// canonicalTargetKey normalizes a host / port pair for upstream stream reuse.
func canonicalTargetKey(host string, port int) string {
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))
}

package config

import "testing"

func TestExampleConfigs(t *testing.T) {
	if _, _, err := LoadServer("../../config.server.example.yaml"); err != nil {
		t.Fatalf("server example: %v", err)
	}
	if _, _, err := LoadClient("../../config.client.example.yaml"); err != nil {
		t.Fatalf("client example: %v", err)
	}
}

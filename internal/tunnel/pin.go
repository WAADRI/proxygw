package tunnel

// SPKI pin rotation window. The panel generates the next key pair and calls
// SetPinNext so nodes learn the upcoming pin through HELLO_ACK before the
// operator switches the certificate.

// SetPinNext updates the pin advertised in HELLO_ACK. Empty string clears it.
func (s *Server) SetPinNext(pin string) {
	s.pinNext.Store(pin)
}

// currentPinNext returns the pin currently advertised to nodes.
func (s *Server) currentPinNext() string {
	v, _ := s.pinNext.Load().(string)
	return v
}

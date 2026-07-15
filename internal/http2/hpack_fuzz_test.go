package http2

import "testing"

// FuzzStatusFromBlock feeds arbitrary bytes to the HPACK response decoder, which
// parses server-controlled input. It must never panic, only return (status, err).
func FuzzStatusFromBlock(f *testing.F) {
	f.Add([]byte{0x88})                      // indexed field, static index 8 (:status 200)
	f.Add([]byte{0x08, 0x03, '4', '0', '4'}) // literal :status via index 8 name... (shape seed)
	f.Add([]byte{0x00})
	f.Add([]byte{0x80})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = statusFromBlock(data)
	})
}

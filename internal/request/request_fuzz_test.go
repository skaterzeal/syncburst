package request

import "testing"

// FuzzParseFile feeds arbitrary bytes to the raw-request parser (which handles
// user-supplied request files) and serializes anything that parses. It must
// never panic.
func FuzzParseFile(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\nHost: example.com\n\n"))
	f.Add([]byte("POST /redeem HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{\"code\":\"X\"}"))
	f.Add([]byte("GET /a HTTP/1.1\nHost: h\n---\nGET /b HTTP/1.1\nHost: h\n"))
	f.Add([]byte("---"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		reqs, err := ParseFile(data)
		if err != nil {
			return
		}
		for i := range reqs {
			_ = reqs[i].RawHTTP1()
			_ = reqs[i].DialAddress()
		}
	})
}

package hook

import "testing"

// FuzzParseSignatureHeader checks the untrusted signature header never panics and never returns a
// signature without a timestamp and at least one decodable value.
func FuzzParseSignatureHeader(f *testing.F) {
	f.Add("")
	f.Add("garbage")
	f.Add("t=1790769600,v1=4f2d927429064bde3d5424e9f8c788e813095e785a2256f4a3a88879a65d6dae")
	f.Add("t=0,v1=00,v1=11")
	f.Add("t=notanumber,v1=x")
	f.Fuzz(func(t *testing.T, header string) {
		sig, err := parseSignatureHeader(header)
		if err == nil && (sig.timestamp.IsZero() || len(sig.values) == 0) {
			t.Fatalf("parseSignatureHeader(%q) returned no timestamp or value without error", header)
		}
	})
}

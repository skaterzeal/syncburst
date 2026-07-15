package http2

import (
	"bytes"
	"testing"

	"github.com/skaterzeal/syncburst/internal/request"
)

func TestHpackIntRoundTrip(t *testing.T) {
	for _, v := range []int{0, 1, 5, 126, 127, 128, 200, 1337, 16383, 16384, 1 << 20} {
		enc := appendHpackInt(nil, v, 7, 0x00)
		got, n, err := readHpackInt(enc, 7)
		if err != nil {
			t.Fatalf("v=%d: %v", v, err)
		}
		if got != v || n != len(enc) {
			t.Errorf("v=%d: got %d (n=%d, enc=%d bytes)", v, got, n, len(enc))
		}
	}
}

func TestStatusIndexed(t *testing.T) {
	// 0x88 = indexed header field, static index 8 => :status 200.
	if s, err := statusFromBlock([]byte{0x88}); err != nil || s != 200 {
		t.Fatalf("indexed :status: got %d err=%v", s, err)
	}
}

func TestStatusLiteralPlain(t *testing.T) {
	// literal without indexing, name index 8 (:status), non-Huffman value "201".
	block := []byte{0x08, 0x03, '2', '0', '1'}
	if s, err := statusFromBlock(block); err != nil || s != 201 {
		t.Fatalf("literal :status: got %d err=%v", s, err)
	}
}

func TestStatusLiteralHuffman409(t *testing.T) {
	// name index 8 (:status), Huffman value "409" = 0x68 0x0f 0xff (see below).
	//   '4'=011010 '0'=00000 '9'=011111, padded to 24 bits with EOS-prefix ones.
	block := []byte{0x08, 0x83, 0x68, 0x0f, 0xff}
	if s, err := statusFromBlock(block); err != nil || s != 409 {
		t.Fatalf("huffman :status 409: got %d err=%v", s, err)
	}
}

func TestHuffmanDigits(t *testing.T) {
	if out, err := decodeHuffman([]byte{0x68, 0x0f, 0xff}); err != nil || string(out) != "409" {
		t.Fatalf(`decodeHuffman => %q err=%v (want "409")`, out, err)
	}
}

func TestNonStatusIgnored(t *testing.T) {
	// literal with new name "x-test: v" must not set a status.
	block := []byte{0x00, 0x06, 'x', '-', 't', 'e', 's', 't', 0x01, 'v'}
	if s, err := statusFromBlock(block); err != nil || s != 0 {
		t.Fatalf("non-status header: got status %d err=%v (want 0)", s, err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello frame")
	buf := appendFrame(nil, frameData, flagEndStream, 7, payload)
	f, err := readFrame(bytes.NewReader(buf), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frameData || f.Flags != flagEndStream || f.StreamID != 7 {
		t.Errorf("frame header mismatch: type=%d flags=%d id=%d", f.Type, f.Flags, f.StreamID)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("payload mismatch: %q", f.Payload)
	}
}

func TestEncodeRequestHeadersRejectsConnectionSpecificHeaders(t *testing.T) {
	base := request.Request{Method: "POST", Scheme: "https", Authority: "example.com", Path: "/", Body: []byte("abc")}
	for _, h := range []request.Header{
		{Name: "connection", Value: "close"},
		{Name: "transfer-encoding", Value: "chunked"},
		{Name: "te", Value: "gzip"},
		{Name: "x-test", Value: "ok\r\ninjected"},
	} {
		r := base
		r.Headers = []request.Header{h}
		if _, err := encodeRequestHeaders(r); err == nil {
			t.Errorf("accepted forbidden/invalid header %#v", h)
		}
	}
}

func TestEncodeRequestHeadersAddsContentLength(t *testing.T) {
	r := request.Request{Method: "POST", Scheme: "https", Authority: "example.com", Path: "/", Body: []byte("abc")}
	block, err := encodeRequestHeaders(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(block, []byte("content-length")) || !bytes.Contains(block, []byte("3")) {
		t.Fatalf("encoded header block lacks generated content-length: %x", block)
	}
}

func TestAppendHeaderFramesRespectsPeerFrameSize(t *testing.T) {
	block := bytes.Repeat([]byte{0x42}, 40_000)
	wire := appendHeaderFrames(nil, 1, block, defaultPeerMaxFrame)
	r := bytes.NewReader(wire)
	frames := 0
	for r.Len() > 0 {
		f, err := readFrame(r, defaultPeerMaxFrame)
		if err != nil {
			t.Fatal(err)
		}
		frames++
		if frames == 1 && f.Type != frameHeaders {
			t.Fatalf("first frame type=%d, want HEADERS", f.Type)
		}
		if frames > 1 && f.Type != frameContinuation {
			t.Fatalf("continuation frame type=%d", f.Type)
		}
		if r.Len() == 0 && f.Flags&flagEndHeaders == 0 {
			t.Fatal("last header frame lacks END_HEADERS")
		}
		if r.Len() > 0 && f.Flags&flagEndHeaders != 0 {
			t.Fatal("non-final header frame has END_HEADERS")
		}
	}
	if frames != 3 {
		t.Fatalf("got %d frames, want 3", frames)
	}
}

func TestAppendDataFramesRespectsPeerFrameSize(t *testing.T) {
	body := bytes.Repeat([]byte{0x7f}, 40_000)
	wire := appendDataFrames(nil, 1, body, defaultPeerMaxFrame)
	r := bytes.NewReader(wire)
	total := 0
	for r.Len() > 0 {
		f, err := readFrame(r, defaultPeerMaxFrame)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type != frameData || f.Flags&flagEndStream != 0 {
			t.Fatalf("unexpected DATA pre-send frame: type=%d flags=%d", f.Type, f.Flags)
		}
		total += len(f.Payload)
	}
	if total != len(body) {
		t.Fatalf("framed %d bytes, want %d", total, len(body))
	}
}

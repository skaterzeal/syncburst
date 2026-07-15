package http2

import "fmt"

// HPACK Huffman decoding in syncburst is deliberately scoped to what the tool
// actually needs to read: numeric ":status" values. syncburst advertises
// HEADER_TABLE_SIZE=0 (see engine setup), so the server never uses the dynamic
// table, and every non-status header string is skipped by its explicit HPACK
// length without being decoded. The only strings ever Huffman-decoded are
// status codes, which consist solely of ASCII digits.
//
// Accordingly this table contains only the RFC 7541 Appendix B codes for the
// digits '0'..'9' (plus EOS for padding validation). These entries are short,
// well-known, and validated as a prefix code at init. decodeHuffman returns an
// error for any other symbol; callers treat that as "status undecodable" and
// fall back to DATA-frame body-length divergence, which never depends on HPACK.

type huffCode struct {
	code uint32
	bits uint8
}

// symbol -> code. Sparse: only digits and EOS are populated.
var huffDigits = map[int]huffCode{
	'0': {0x0, 5}, '1': {0x1, 5}, '2': {0x2, 5}, '3': {0x19, 6}, '4': {0x1a, 6},
	'5': {0x1b, 6}, '6': {0x1c, 6}, '7': {0x1d, 6}, '8': {0x1e, 6}, '9': {0x1f, 6},
	huffEOS: {0x3fffffff, 30},
}

const huffEOS = 256

type huffNode struct {
	child  [2]*huffNode
	sym    int
	isLeaf bool
}

var huffRoot = buildHuffTrie()

func buildHuffTrie() *huffNode {
	root := &huffNode{sym: -1}
	for sym, hc := range huffDigits {
		node := root
		for i := int(hc.bits) - 1; i >= 0; i-- {
			b := (hc.code >> uint(i)) & 1
			next := node.child[b]
			if next == nil {
				next = &huffNode{sym: -1}
				node.child[b] = next
			}
			node = next
		}
		if node.isLeaf || node.child[0] != nil || node.child[1] != nil {
			panic(fmt.Sprintf("huffman digit table is not a prefix code at symbol %d", sym))
		}
		node.isLeaf = true
		node.sym = sym
	}
	return root
}

// decodeHuffman decodes an HPACK Huffman string composed of digits. It returns
// an error if the string contains any non-digit symbol.
func decodeHuffman(data []byte) ([]byte, error) {
	out := make([]byte, 0, len(data)*8/5)
	node := huffRoot
	nbits := 0
	for _, bt := range data {
		for i := 7; i >= 0; i-- {
			b := (bt >> uint(i)) & 1
			if node.child[b] == nil {
				return nil, fmt.Errorf("huffman: unsupported symbol (non-digit)")
			}
			node = node.child[b]
			nbits++
			if node.isLeaf {
				if node.sym == huffEOS {
					return nil, fmt.Errorf("huffman: EOS in input")
				}
				out = append(out, byte(node.sym))
				node = huffRoot
				nbits = 0
			}
		}
	}
	if nbits >= 8 {
		return nil, fmt.Errorf("huffman: padding too long")
	}
	// Trailing bits are EOS-prefix padding (all ones); node must be on an
	// all-ones path from the root.
	for n := node; n != huffRoot; {
		if n.child[0] != nil && n.child[1] == nil {
			return nil, fmt.Errorf("huffman: bad padding")
		}
		if n.child[1] == nil {
			break
		}
		n = n.child[1]
	}
	return out, nil
}

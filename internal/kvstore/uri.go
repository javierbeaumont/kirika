// kirika: private analytics from HTTP access logs
//
// Copyright (C) 2026 Javier Beaumont <javierbeaumont@users.noreply.github.com>
//
// This file is part of kirika.
//
// kirika is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// kirika is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with kirika. If not, see <https://www.gnu.org/licenses/>.

package kvstore

import "strings"

// The hex digits of an escape that a conversion writes, in upper case (RFC 3986, section 6.2.2.1).
const upperHex = "0123456789ABCDEF"

// Returns uri, a path or a referrer, in one spelling of the forms that differ only in their percent-encoding (RFC 3986,
// section 6.2.2), whichever way the log wrote it. An escape of an unreserved character is decoded (section 2.3), and
// any other keeps its escape in upper-case hex. A reserved character stays as written, raw or escaped: its escape may
// mean something else. Any other byte written raw is escaped, such as a space or a byte of UTF-8, as RFC 3987, section
// 3.1, maps an IRI to a URI. A lone "%" is escaped too: it could otherwise join the hex digits after it into an escape.
// So "/a%c3%b1o" and the same path sent raw are both "/a%C3%B1o".
func canonicalURI(uri string) string {
	if plainURI(uri) {
		return uri
	}

	var converted strings.Builder

	converted.Grow(len(uri))

	for at := 0; at < len(uri); {
		value, width := octetAt(uri, at)

		switch escaped := width == 3; {
		case escaped && isUnreserved(value), !escaped && rawASCII(value):
			converted.WriteByte(value)
		default:
			writeEscape(&converted, value)
		}

		at += width
	}

	return converted.String()
}

// Reports whether uri holds only the ASCII characters a URI holds as themselves, and no escape: canonicalURI returns it
// as it is.
func plainURI(uri string) bool {
	for i := range len(uri) {
		if !rawASCII(uri[i]) {
			return false
		}
	}

	return true
}

// Returns the octet at index at of uri and the bytes it takes: an escape, "%" and two hex digits, or a byte as it is.
func octetAt(uri string, at int) (value byte, width int) {
	if uri[at] == '%' && at+2 < len(uri) && isHex(uri[at+1]) && isHex(uri[at+2]) {
		return unhex(uri[at+1])<<4 | unhex(uri[at+2]), 3
	}

	return uri[at], 1
}

func writeEscape(converted *strings.Builder, octet byte) {
	converted.WriteByte('%')
	converted.WriteByte(upperHex[octet>>4])
	converted.WriteByte(upperHex[octet&0xF])
}

// The unreserved characters of a URI (RFC 3986, section 2.3).
const unreservedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// The ASCII characters a URI holds as themselves, a bit each: the unreserved and the reserved ones (section 2.2).
var rawASCIISet = bitSet(unreservedChars + ":/?#[]@!$&'()*+,;=")

// The unreserved characters, a bit each.
var unreservedSet = bitSet(unreservedChars)

// Returns the set of the ASCII characters in chars, a bit each.
func bitSet(chars string) (set [2]uint64) {
	for _, octet := range []byte(chars) {
		set[octet/64] |= 1 << (octet % 64)
	}

	return set
}

// Reports whether a URI holds octet as itself.
func rawASCII(octet byte) bool {
	return octet < 0x80 && rawASCIISet[octet/64]&(1<<(octet%64)) != 0
}

func isUnreserved(octet byte) bool {
	return octet < 0x80 && unreservedSet[octet/64]&(1<<(octet%64)) != 0
}

func isHex(octet byte) bool {
	return '0' <= octet && octet <= '9' || 'a' <= octet && octet <= 'f' || 'A' <= octet && octet <= 'F'
}

func unhex(octet byte) byte {
	switch {
	case octet <= '9':
		return octet - '0'
	case octet >= 'a':
		return octet - 'a' + 10
	default:
		return octet - 'A' + 10
	}
}

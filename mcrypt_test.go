/*
 * Copyright (c) 2014 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package mcrypt

import (
	"bytes"
	//"os"
	//"reflect"
	"encoding/binary"
	"testing"
)

var (
	alice *Identity
	bob   *Identity
)

func TestIdentity(t *testing.T) {
	var err error

	alice, err = NewIdentity("Alice", "alice@localhost")
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("alice fingerprint: %v", alice.PublicIdentity.Fingerprint())

	bob, err = NewIdentity("Bob", "bob@localhost")
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("bob fingerprint: %v", bob.PublicIdentity.Fingerprint())

	msg := []byte("encrypt this, and that")
	c, err := alice.Encrypt(bob.PublicIdentity.Key, msg)
	if err != nil {
		t.Error("Could not encrypt")
		return
	}
	t.Logf("%02x", msg)
	t.Logf("%02x", c.Box)
	ct, err := bob.Decrypt(alice.PublicIdentity.Key, c)
	if err != nil {
		t.Error("Could not decrypt")
		return
	}
	t.Logf("%02x", ct)

	if !bytes.Equal(msg, ct) {
		t.Error("Corruption")
		return
	}
}

func TestMarshalPublicIdentity(t *testing.T) {
	j, err := alice.PublicIdentity.Marshal()
	if err != nil {
		t.Error(err)
	}
	t.Logf("%s", j)
	p, err := UnmarshalPublicIdentity(j)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(alice.PublicIdentity.Key[:], p.Key[:]) {
		t.Errorf("UnmarshalPublicIdentity Key")
	}
	if !bytes.Equal(alice.PublicIdentity.Signature[:], p.Signature[:]) {
		t.Errorf("UnmarshalPublicIdentity Signature")
	}
}

func TestMarshalIdentity(t *testing.T) {
	j, err := bob.Marshal()
	if err != nil {
		t.Error(err)
	}
	t.Logf("%s", j)
	p, err := UnmarshalIdentity(j)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(bob.Key[:], p.Key[:]) {
		t.Errorf("UnmarshalIdentity Key")
	}
}

func TestUint64(t *testing.T) {
	var x uint64 = 0xdeadbeefface1234
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, x)

	c, err := alice.Encrypt(bob.PublicIdentity.Key, b)
	if err != nil {
		t.Error("Could not encrypt")
		return
	}
	t.Logf("size %v Box %02x", len(c.Box), c.Box)
	ct, err := bob.Decrypt(alice.PublicIdentity.Key, c)
	if err != nil {
		t.Error("Could not decrypt")
		return
	}
	t.Logf("%02x", ct)
}

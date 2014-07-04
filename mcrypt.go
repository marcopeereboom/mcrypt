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

// mcrypt (Message Crypto) uses NaCl encrypt and authenticate messages using
// Curve25519, XSalsa20 and Poly1305.  The length of messages is not hidden.
// Additionally it can digitally sign messages or content using the Ed25519
// signature algorithm.
//
// See http://nacl.cr.yp.to/box.html for more information on NaCl.

package mcrypt

// XXX
// REMOVE ALL ERRORS AND REPLACE WITH BOOL
// XXX

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"code.google.com/p/go.crypto/nacl/box"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
)

const (
	signatureSize    = 64
	privKeySize      = 64
	priv25519KeySize = 32
	pubKeySize       = 32
	NonceSize        = 24
)

var (
	prng = rand.Reader
)

type Identity struct {
	PublicIdentity PublicIdentity
	Key            *[privKeySize]byte // private key, exported for JSON
}

type Identifier struct {
	Description string // explain what the content is
	Mime        string // mime type to describe Content
	Content     []byte // picture, audio etc
}

type PublicIdentity struct {
	Name        string
	Address     string
	Key         *[pubKeySize]byte
	Signature   *[signatureSize]byte
	Identifiers []*Identifier
}

type Message struct {
	Nonce     [NonceSize]byte      // NOT secret
	Signature *[signatureSize]byte // signature of the encrypted box
	Box       []byte               // NaCl box
}

// Zero out a byte slice.
func zero(in []byte) {
	if in == nil {
		return
	}
	inlen := len(in)
	for i := 0; i < inlen; i++ {
		in[i] ^= in[i]
	}
}

func NewIdentifier(description, filename string) (*Identifier, error) {
	var err error

	i := Identifier{}
	i.Content, err = ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	i.Mime = http.DetectContentType(i.Content)
	i.Description = description

	return &i, nil
}

func (m *Message) Marshal() ([]byte, error) {
	j, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func UnmarshalMessage(blob []byte) (*Message, error) {
	m := &Message{}
	err := json.Unmarshal(blob, m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (p *PublicIdentity) Marshal() ([]byte, error) {
	j, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func UnmarshalPublicIdentity(blob []byte) (*PublicIdentity, error) {
	p := &PublicIdentity{}
	err := json.Unmarshal(blob, p)
	if err != nil {
		return nil, err
	}
	if !p.Verify() {
		return nil, fmt.Errorf("Verify")
	}
	return p, err
}

// Verify authenticity of public key
func (p *PublicIdentity) Verify() bool {
	return ed25519.Verify(p.Key, p.Key[:], p.Signature)
}

// Finger print public key
func (p *PublicIdentity) Fingerprint() string {
	digest := sha256.Sum256(p.Key[:])
	f := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		digest[0],
		digest[1],
		digest[2],
		digest[3],
		digest[4],
		digest[5],
		digest[6],
		digest[7],
		digest[8],
		digest[9],
	)
	return f
}
func NewIdentity(name, address string) (*Identity, error) {
	var err error

	i := Identity{}
	i.PublicIdentity.Key, i.Key, err = ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	i.PublicIdentity.Name = name
	i.PublicIdentity.Address = address

	// sign and verify that it worked
	i.PublicIdentity.Signature = ed25519.Sign(i.Key,
		i.PublicIdentity.Key[:])
	if !i.PublicIdentity.Verify() {
		return nil, fmt.Errorf("could not verify public signature")
	}

	return &i, nil
}

func (i *Identity) Marshal() ([]byte, error) {
	j, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func UnmarshalIdentity(blob []byte) (*Identity, error) {
	i := &Identity{}
	err := json.Unmarshal(blob, i)
	if err != nil {
		return nil, err
	}
	if !i.PublicIdentity.Verify() {
		return nil, fmt.Errorf("Verify")
	}
	return i, err
}

func (i *Identity) Encrypt(peer *[pubKeySize]byte, msg []byte) (*Message, error) {
	// generate random non secret nonce
	m := Message{}
	_, err := io.ReadFull(prng, m.Nonce[:])
	if err != nil {
		return nil, err
	}

	// convert ed25519 to curve25519
	var (
		ourPrivKey  [priv25519KeySize]byte
		theirPubKey [pubKeySize]byte
	)
	extra25519.PrivateKeyToCurve25519(&ourPrivKey, i.Key)
	defer zero(ourPrivKey[:])
	if !extra25519.PublicKeyToCurve25519(&theirPubKey, peer) {
		return nil, fmt.Errorf("PublicKeyToCurve25519")
	}
	defer zero(theirPubKey[:])

	// encrypt
	m.Box = box.Seal(nil, msg, &m.Nonce, &theirPubKey, &ourPrivKey)

	// sign
	m.Signature = ed25519.Sign(i.Key, m.Box)

	return &m, nil
}

func (i *Identity) Decrypt(peer *[pubKeySize]byte, msg *Message) ([]byte, error) {
	// convert ed25519 to curve25519
	var (
		ourPrivKey  [priv25519KeySize]byte
		theirPubKey [pubKeySize]byte
	)
	extra25519.PrivateKeyToCurve25519(&ourPrivKey, i.Key)
	defer zero(ourPrivKey[:])
	if !extra25519.PublicKeyToCurve25519(&theirPubKey, peer) {
		return []byte{}, fmt.Errorf("PublicKeyToCurve25519")
	}
	defer zero(theirPubKey[:])

	// verify signature
	ok := ed25519.Verify(peer, msg.Box, msg.Signature)
	if !ok {
		return []byte{}, fmt.Errorf("Verify")
	}

	// decrypt
	ct, ok := box.Open(nil, msg.Box, &msg.Nonce, &theirPubKey, &ourPrivKey)
	if !ok {
		return []byte{}, fmt.Errorf("Open")
	}
	return ct, nil
}

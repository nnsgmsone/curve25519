package curve25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"hash"

	"github.com/infinivision/anonymous/curve25519/edwards25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

func GenHash(h hash.Hash, data []byte) []byte {
	h.Reset()
	h.Write(data)
	return h.Sum(nil)
}

func Sign(priv []byte, m []byte) []byte {
	if len(priv) != 64 {
		return nil
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), m)
}

func Verify(pub []byte, m, s []byte) bool {
	if len(pub) != 32 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), m, s)
}

func Encrypt(pub []byte, m []byte) []byte {
	if len(pub) != 32 {
		return nil
	}
	length := len(m)
	R, r, err := ed25519.GenerateKey(rand.Reader) // R = r *  G
	if err != nil {
		return nil
	}
	{
		digest := sha512.Sum512(r[:32])
		digest[0] &= 0xF8
		digest[31] &= 0x7F
		digest[31] |= 0x40
		r = digest[:32]
	}
	z := ScalarMult(pub, r) // z = r * d * G
	c := []byte{}
	c = append(c, R...)                                       // R = r * G
	c = append(c, GenHash(sha3.New256(), append(z, m...))...) // H(z|m)
	c = append(c, pbkdf2.Key(z, R, 4096, length, sha3.New256)...)
	for i := 0; i < length; i++ {
		c[64+i] ^= m[i]
	}
	return c
}

func Decrypt(priv []byte, c []byte) []byte {
	{
		digest := sha512.Sum512(priv[:32])
		digest[0] &= 0xF8
		digest[31] &= 0x7F
		digest[31] |= 0x40
		priv = digest[:32]
	}
	length := len(c) - 64
	z := ScalarMult(c[:32], priv) // z = R *d = r * G * d
	m := pbkdf2.Key(z, c[:32], 4096, length, sha3.New256)
	for i := 0; i < length; i++ {
		m[i] ^= c[i+64]
	}
	if bytes.Compare(GenHash(sha3.New256(), append(z, m...)), c[32:64]) != 0 {
		return nil
	}
	return m
}

func Add(x1, x2 []byte) []byte {
	var c edwards25519.CachedGroupElement
	var cp edwards25519.CompletedGroupElement
	var e, e1, e2 edwards25519.ExtendedGroupElement

	if len(x1) != 32 || len(x2) != 32 {
		return nil
	}
	if e1.FromBytes(fromSlice(x1)) && e1.IsOnCurve() &&
		e2.FromBytes(fromSlice(x2)) && e2.IsOnCurve() {
		var x [32]byte
		e2.ToCached(&c)
		edwards25519.GeAdd(&cp, &e1, &c)
		cp.ToExtended(&e)
		e.ToBytes(&x)
		return x[:]
	}
	return nil
}

func Sub(x1, x2 []byte) []byte {
	var c edwards25519.CachedGroupElement
	var cp edwards25519.CompletedGroupElement
	var e, e1, e2 edwards25519.ExtendedGroupElement

	if len(x1) != 32 || len(x2) != 32 {
		return nil
	}
	if e1.FromBytes(fromSlice(x1)) && e1.IsOnCurve() &&
		e2.FromBytes(fromSlice(x2)) && e2.IsOnCurve() {
		var x [32]byte
		e2.ToCached(&c)
		edwards25519.GeSub(&cp, &e1, &c)
		cp.ToExtended(&e)
		e.ToBytes(&x)
		return x[:]
	}
	return nil
}

func ScalarMult(x1 []byte, k []byte) []byte {
	var x [32]byte
	var e, e1 edwards25519.ExtendedGroupElement

	if len(k) != 32 || len(x1) != 32 || !e1.FromBytes(fromSlice(x1)) {
		return nil
	}
	edwards25519.ScalarMult(&e, &e1, fromSlice(k))
	e.ToBytes(&x)
	return x[:]
}

func ScalarBaseMult(k []byte) []byte {
	var x [32]byte
	var e edwards25519.ExtendedGroupElement

	if len(k) != 32 {
		return nil
	}
	edwards25519.GeScalarMultBase(&e, fromSlice(k))
	e.ToBytes(&x)
	return x[:]
}

/*
 * -x^2 + y^2 = 1 + d * x^2 * y^2
 * x = X / z, y = Y / z, y = Y/Z
 */
func IsOnCurve(x []byte) bool {
	var e edwards25519.ExtendedGroupElement

	if len(x) != 32 {
		return false
	}
	if !e.FromBytes(fromSlice(x)) {
		return false
	}
	return e.IsOnCurve()
}

func fromSlice(x []byte) *[32]byte {
	var y [32]byte

	copy(y[:], x)
	return &y
}

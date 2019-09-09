package curve25519

import (
	"crypto/rand"
	"fmt"
	"log"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func Test(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	{
		msg := []byte("test")
		c := Encrypt([]byte(pub), msg)
		fmt.Printf("m: %s\n", Decrypt([]byte(priv), c))
	}
	{
		msg := []byte("test")
		s := Sign([]byte(priv), msg)
		fmt.Printf("verify: %v\n", Verify([]byte(pub), msg, s))
	}
}

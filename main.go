package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"os"
)

var (
	oidExtensionKeyUsage       = []int{2, 5, 29, 15}
)

func main() {
	//PKCS#1 format RSA PrivateKey [RFC8017]
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	//PKCS#1 format RSA PublicKey
	var publicKey crypto.PublicKey
	publicKey = privateKey.Public()

	var ku x509.KeyUsage
	ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
	kex, err := marshalKeyUsage(ku)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	template := &x509.CertificateRequest{
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          publicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,

		Subject: pkix.Name{
			CommonName:         "www.example.org",
			OrganizationalUnit: []string{"Example Org Unit"},
			Organization:       []string{"Example Org"},
			Country:            []string{"JP"},
		},

		DNSNames:        []string{"www.example.com", "www.example.co.jp"},
		ExtraExtensions: []pkix.Extension{kex},
	}

	//PKCS#10 Certification Request [RFC2986]
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)

	//Convert to ASN.1 DER encoded form
	f, err := os.Create("goExtDer.csr")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	_, err = f.Write(csr)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("goExtPem.csr")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

}

//Copied and Modified from x509 package
func marshalKeyUsage(ku x509.KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionKeyUsage}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return ext, err
	}
	return ext, nil
}

//Copied from x509 package
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

//Copied from x509 package
// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

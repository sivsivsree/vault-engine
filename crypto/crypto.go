package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	vault          = "vault"
	public         = vault + "/public"
	credentials    = vault + "/credentials"
	secretJSON     = "secret.json"
	publicKeyFile  = public + "/pub.pem"
	PrivateKeyFile = credentials + "/priv.pem"
	Encrypted      = credentials + "/secret.Encrypted"
)

func makeDIR() {

	if _, err := os.Stat(vault); os.IsNotExist(err) {
		_ = os.Mkdir(vault, os.ModePerm)
	}

	if _, err := os.Stat(public); os.IsNotExist(err) {
		_ = os.Mkdir(public, os.ModePerm)
	}

	if _, err := os.Stat(credentials); os.IsNotExist(err) {
		_ = os.Mkdir(credentials, os.ModePerm)
	}
}

// Create is used to create a random RSA private key
// with bitSize 4096
func Create() *rsa.PrivateKey {

	makeDIR()
	privateKey, err := generatePrivateKey(4096)
	if err != nil {
		log.Fatal("Private key generation failed")
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	if err := ioutil.WriteFile(PrivateKeyFile, pemdata, 0600); err != nil {
		log.Fatalf("writing private key failed: %s", err)
	}
	return privateKey
}

// ParseKey is used to get private key from a file
func ParseKey(privateKey string) *rsa.PrivateKey {

	makeDIR()

	pemData, err := ioutil.ReadFile(privateKey)
	if err != nil {
		log.Fatalf("read key file: %s", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	return priv
}

// PublicKey is a function used to extract public key from
// private key and writes it to 'public/pub.pem'
func PublicKey(private *rsa.PrivateKey) string {

	asn1Bytes, err := asn1.Marshal(private.PublicKey)

	if err != nil {
		log.Fatalf("encrypt: %s", err)
	}

	var pemKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	publicKey := pem.EncodeToMemory(pemKey)
	if err := ioutil.WriteFile(publicKeyFile, publicKey, 0600); err != nil {
		log.Fatalf("write output: %s", err)
	}
	return string(publicKey)
}

// DecryptFile is used to decrypt the Encrypted file using Private Key
func DecryptFile(private *rsa.PrivateKey, label string) string {

	//private := parseKey(privateKey)

	if label == "" {
		log.Fatal("pass is not present")
	}

	in, err := ioutil.ReadFile(Encrypted)
	if err != nil {
		log.Fatalf("input file: %s", err)
	}

	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, private, in, []byte(label))
	if err != nil {
		fmt.Println(err)
		log.Fatalf("Decrypt Error :: %s", err)
	}

	//if err := ioutil.WriteFile(decrypted, out, 0600); err != nil {
	//	log.Fatalf("write output: %s", err)
	//}

	return string(out)

}

// EncryptFile is used to Encrypt the file using Public Key
func EncryptFile(priv *rsa.PrivateKey, label string, testMode bool) {
	// Read the input file
	in, err := ioutil.ReadFile(secretJSON)

	if err != nil {
		log.Fatalf("input file: %s", err)
	}

	if label == "" {
		log.Fatal("pass is not present")
	}

	out, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, in, []byte(label))

	if err != nil {
		log.Fatalf("encrypt: %s", err)
	}

	if err := ioutil.WriteFile(Encrypted, out, 0600); err != nil {
		log.Fatalf("write output: %s", err)
	}

	if testMode {
		if err := os.Remove(secretJSON); err != nil {
			log.Fatalf("Failed to remove the Secret.json file : %s", err)
		}
	}

}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

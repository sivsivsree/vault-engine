package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sivsivsree/vault/crypto"
	"log"
	"net/http"
	"os"
	"time"
)

// Command-line flags
var (
	label = flag.String("pass", "", "Label to use (filename by default)")
	test  = flag.Bool("prod", true, "Use for test, the secret.json wont be deleted")
)

//  openssl genrsa -out priv.pem 2048

var privateKey *rsa.PrivateKey

func main() {
	flag.Parse()

	fmt.Println("Production mode =", *test)
	if _, err := os.Stat(crypto.PrivateKeyFile); os.IsNotExist(err) {
		privateKey = crypto.Create() // no private key exists and need to create one ans save in PRIVATEKEY.
	} else {
		privateKey = crypto.ParseKey(crypto.PrivateKeyFile)
		fmt.Println("Private key exists")
	}

	if _, err := os.Stat(crypto.Encrypted); os.IsNotExist(err) {
		crypto.EncryptFile(privateKey, *label, *test)
	} else {
		fmt.Println("Encrypted exists")

	}

	r := mux.NewRouter()
	r.HandleFunc("/config", DecryptHandler).Methods("GET")

	srv := &http.Server{
		Handler: r,
		Addr:    "0.0.0.0:9211",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	fmt.Println(crypto.PublicKey(privateKey))

	fmt.Println("Vault listening on port 9211")
	log.Fatal(srv.ListenAndServe())

}

// DecryptHandler is used to consume the encrypted data from the
// vault engine.
func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	data := crypto.DecryptFile(privateKey, *label)
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(data), &result)
	_ = json.NewEncoder(w).Encode(result)
}

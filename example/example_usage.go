package main

import (
	"fmt"
	"log"

	"github.com/iamgaru/vault"
)

func main() {
	log.Println("Creating a new vault...")
	vaultInstance, err := vault.NewVault("")
	if err != nil {
		log.Fatalf("Failed to create vault: %v", err)
	}

	log.Println("Storing a secret with ID 'my-secret'...")
	err = vaultInstance.StoreSecret("my-secret", "secret-value")
	if err != nil {
		log.Fatalf("Failed to store secret: %v", err)
	}

	log.Println("Retrieving the secret with ID 'my-secret'...")
	value, err := vaultInstance.GetSecret("my-secret")
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	log.Printf("Retrieved secret: %s\n", value)
	fmt.Printf("Retrieved secret: %s\n", value)
}

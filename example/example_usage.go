package main

import (
	"fmt"
	"log"
)

func main() {
	// Create a new vault
	vaultInstance, err := main.NewVault("")
	if err != nil {
		log.Fatalf("Failed to create vault: %v", err)
	}

	// Store a secret
	err = vaultInstance.StoreSecret("my-secret", "secret-value")
	if err != nil {
		log.Fatalf("Failed to store secret: %v", err)
	}

	// Retrieve a secret
	value, err := vaultInstance.GetSecret("my-secret")
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Retrieved secret: %s\n", value)
}

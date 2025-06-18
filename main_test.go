package main

import (
	"testing"
)

func TestVaultStoreAndGetSecret(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVault(dir)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	id := "test-id"
	value := "super-secret-value"

	// Store secret
	err = vault.StoreSecret(id, value)
	if err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Retrieve secret
	got, err := vault.GetSecret(id)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}
	if got != value {
		t.Errorf("Expected %q, got %q", value, got)
	}
}

func TestVaultEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVault(dir)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	plaintext := "encrypt-me"
	ciphertext, err := vault.encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := vault.decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
}

func TestVaultGetSecretNotFound(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVault(dir)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	_, err = vault.GetSecret("does-not-exist")
	if err == nil {
		t.Error("Expected error for missing secret, got nil")
	}
}

func TestVaultStoreSecretInvalidID(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVault(dir)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	err = vault.StoreSecret("", "value")
	if err == nil {
		t.Error("Expected error for empty ID, got nil")
	}
}

func TestVaultStoreSecretEmptyValue(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVault(dir)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	err = vault.StoreSecret("id", "")
	if err == nil {
		t.Error("Expected error for empty value, got nil")
	}
}

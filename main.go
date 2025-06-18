package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort = "8123"
	dataDir     = ".vault"
	secretsFile = "secrets.json"
	authFile    = "auth.json"
)

// Vault represents a secure storage for secrets
type Vault struct {
	mutex   sync.Mutex
	secrets map[string]string
	ecKey   *ecdsa.PrivateKey
	logger  *log.Logger
	authKey string
	dataDir string
}

// NewVault creates a new Vault instance
func NewVault(dataDirPath string) (*Vault, error) {
	if dataDirPath == "" {
		dataDirPath = dataDir
	}

	v := &Vault{
		secrets: make(map[string]string),
		logger:  log.New(log.Writer(), "[VAULT] ", log.LstdFlags|log.Lshortfile),
		dataDir: dataDirPath,
	}

	// Generate ECDSA key
	var err error
	v.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %v", err)
	}

	// Create data directory
	if err := os.MkdirAll(v.dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	// Load or generate auth key
	authKeyPath := filepath.Join(v.dataDir, authFile)
	if _, err := os.Stat(authKeyPath); os.IsNotExist(err) {
		v.authKey = generateAuthKey()
		if err := v.saveAuthKey(authKeyPath); err != nil {
			return nil, fmt.Errorf("failed to save auth key: %v", err)
		}
	} else {
		if err := v.loadAuthKey(authKeyPath); err != nil {
			return nil, fmt.Errorf("failed to load auth key: %v", err)
		}
	}

	// Load existing secrets
	if err := v.loadSecrets(); err != nil {
		v.logger.Printf("No existing secrets found or error loading: %v", err)
	}

	return v, nil
}

// GetAuthKey returns the current authentication key
func (v *Vault) GetAuthKey() string {
	return v.authKey
}

// StoreSecret stores a secret with the given ID
func (v *Vault) StoreSecret(id, value string) error {
	if err := validateID(id); err != nil {
		return fmt.Errorf("invalid id: %v", err)
	}

	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	encryptedValue, err := v.encrypt(value)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	v.mutex.Lock()
	v.secrets[id] = encryptedValue
	v.mutex.Unlock()

	if err := v.saveSecrets(); err != nil {
		return fmt.Errorf("failed to save secrets: %v", err)
	}

	return nil
}

// GetSecret retrieves a secret by ID
func (v *Vault) GetSecret(id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", fmt.Errorf("invalid id: %v", err)
	}

	v.mutex.Lock()
	encryptedValue, ok := v.secrets[id]
	v.mutex.Unlock()

	if !ok {
		return "", fmt.Errorf("secret not found")
	}

	value, err := v.decrypt(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return value, nil
}

func (v *Vault) encrypt(plaintext string) (string, error) {
	hash := sha256.Sum256(v.ecKey.D.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		v.logger.Printf("Encryption failed to create cipher: %v", err)
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		v.logger.Printf("Encryption failed to create GCM: %v", err)
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		v.logger.Printf("Encryption failed to generate nonce: %v", err)
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	v.logger.Printf("Encrypted secret (len=%d)", len(ciphertext))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (v *Vault) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		v.logger.Printf("Decryption failed to decode base64: %v", err)
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	hash := sha256.Sum256(v.ecKey.D.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		v.logger.Printf("Decryption failed to create cipher: %v", err)
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		v.logger.Printf("Decryption failed to create GCM: %v", err)
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		v.logger.Printf("Decryption failed: ciphertext too short")
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		v.logger.Printf("Decryption failed to open: %v", err)
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	v.logger.Printf("Decrypted secret (len=%d)", len(plaintext))
	return string(plaintext), nil
}

func (v *Vault) saveAuthKey(path string) error {
	return os.WriteFile(path, []byte(v.authKey), 0600)
}

func (v *Vault) loadAuthKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v.authKey = string(data)
	return nil
}

func (v *Vault) loadSecrets() error {
	path := filepath.Join(v.dataDir, secretsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &v.secrets)
}

func (v *Vault) saveSecrets() error {
	path := filepath.Join(v.dataDir, secretsFile)
	data, err := json.Marshal(v.secrets)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func generateAuthKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate auth key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("id cannot be empty")
	}
	if len(id) > 100 {
		return fmt.Errorf("id too long")
	}
	if strings.ContainsAny(id, " \t\n\r") {
		return fmt.Errorf("id contains invalid characters")
	}
	return nil
}

// HTTP handlers for the web service
func (v *Vault) storeSecretHandler(w http.ResponseWriter, r *http.Request) {
	if !v.authenticateRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		v.logger.Printf("Invalid request: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := v.StoreSecret(req.ID, req.Value); err != nil {
		v.logger.Printf("Failed to store secret: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Stored secret with ID: %s", req.ID)
}

func (v *Vault) getSecretHandler(w http.ResponseWriter, r *http.Request) {
	if !v.authenticateRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	value, err := v.GetSecret(id)
	if err != nil {
		v.logger.Printf("Failed to get secret: %v", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	resp := map[string]string{
		"id":    id,
		"value": value,
		"ts":    time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(resp)
}

func (v *Vault) authenticateRequest(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	return auth == "Bearer "+v.authKey
}

// StartServer starts the HTTP server
func (v *Vault) StartServer(port string) error {
	if port == "" {
		port = defaultPort
	}

	http.HandleFunc("/store", v.storeSecretHandler)
	http.HandleFunc("/get", v.getSecretHandler)

	v.logger.Printf("Vault running at http://localhost:%s", port)
	v.logger.Printf("Auth key: %s", v.authKey)
	return http.ListenAndServe(":"+port, nil)
}

// Example usage as a library
func ExampleUsage() {
	// Create a new vault
	vault, err := NewVault("")
	if err != nil {
		log.Fatalf("Failed to create vault: %v", err)
	}

	// Store a secret
	err = vault.StoreSecret("my-secret", "secret-value")
	if err != nil {
		log.Fatalf("Failed to store secret: %v", err)
	}

	// Retrieve a secret
	value, err := vault.GetSecret("my-secret")
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Retrieved secret: %s\n", value)
}

func main() {
	// Create a new vault
	vault, err := NewVault("")
	if err != nil {
		log.Fatalf("Failed to create vault: %v", err)
	}

	// Start the HTTP server
	port := os.Getenv("VAULT_PORT")
	if err := vault.StartServer(port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

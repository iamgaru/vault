
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"
)

var (
    mutex   sync.Mutex
    secrets = make(map[string]string)
    ecKey   *ecdsa.PrivateKey
)

func init() {
    var err error
    ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }
}

func storeSecretHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ID    string `json:"id"`
        Value string `json:"value"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    secrets[req.ID] = req.Value
    mutex.Unlock()

    fmt.Fprintf(w, "Stored secret with ID: %s", req.ID)
}

func getSecretHandler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    if id == "" {
        http.Error(w, "missing id", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    value, ok := secrets[id]
    mutex.Unlock()

    if !ok {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }

    resp := map[string]string{
        "id":    id,
        "value": value,
        "ts":    time.Now().Format(time.RFC3339),
    }
    json.NewEncoder(w).Encode(resp)
}

func main() {
    http.HandleFunc("/store", storeSecretHandler)
    http.HandleFunc("/get", getSecretHandler)

    fmt.Println("Vault sidecar running at http://localhost:8123")
    log.Fatal(http.ListenAndServe(":8123", nil))
}

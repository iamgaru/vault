# Secure Vault

A lightweight, cross-platform secret storage solution that can be used as both a library and a service.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Client         │     │  Vault Service  │     │  Storage        │
│                 │     │                 │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │   Store/Get Secret    │                       │
         │──────────────────────>│                       │
         │                       │                       │
         │                       │   Encrypt/Decrypt     │
         │                       │<─────────────────────>│
         │                       │                       │
         │                       │   Read/Write File     │
         │                       │──────────────────────>│
         │                       │                       │
         │   Response            │                       │
         │<──────────────────────│                       │
         │                       │                       │
```

## Features

- Cross-platform (Windows, macOS, Linux)
- Encrypted storage using AES-GCM
- Simple authentication
- Can be used as a library or service
- Persistent storage
- Thread-safe operations

## Usage

### As a Library

```go
package main

import "github.com/yourusername/vault"

func main() {
    // Create a new vault
    v, err := vault.NewVault("")
    if err != nil {
        log.Fatal(err)
    }

    // Store a secret
    err = v.StoreSecret("my-secret", "secret-value")
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve a secret
    value, err := v.GetSecret("my-secret")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(value)
}
```

### As a Service

1. Build and run:
```bash
go build
./vault
```

2. Use the HTTP API:
```bash
# Store a secret
curl -X POST http://localhost:8123/store \
  -H "Authorization: Bearer YOUR_AUTH_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"my-secret","value":"secret-value"}'

# Retrieve a secret
curl http://localhost:8123/get?id=my-secret \
  -H "Authorization: Bearer YOUR_AUTH_KEY"
```

## Configuration

- `VAULT_PORT`: Set custom port (default: 8123)
- Data directory: Customizable via `NewVault(dataDirPath string)`

## Security

- Secrets are encrypted using AES-GCM
- Authentication required for all operations
- File permissions set to 0600 (user-only read/write)
- Secure key generation using crypto/rand

## Process Flow

1. **Initialization**:
   - Generate ECDSA key
   - Create/load auth key
   - Initialize storage

2. **Store Secret**:
   - Validate input
   - Encrypt secret
   - Store encrypted data
   - Persist to disk

3. **Retrieve Secret**:
   - Validate request
   - Load encrypted data
   - Decrypt secret
   - Return value

## License

MIT License 
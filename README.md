# Enclaive Coding Challenge 2: Keysafe
This repository implements a minimal security management service called KeySafe. Keysafe should allow users to:
- create cryptographic keys
- encrypt data using stored keys
- decrypt previously encrypted data
- list available keys

For more information about the detail requirements:
https://docs.google.com/document/d/1xCU4lTI28lcYm7_n_H5Z7mR4l322-H-Z3Qpw3zlN0bQ/edit?usp=sharing

Important to note, all architecture, design and code have beend developed by an Human. No LLM was used in this context.

## Table of contents
- [Planning](#planning)
- [Architecture and design choices](#architecture-and-design-choices)
  - [Project structure](#project-structure)
- [Security considerations](#security-considerations)
- [How to run the service](#how-to-run-the-service)
  - [Smoke test the service](#smoke-test-the-service)
    - [Expected results](#expected-results)
- [How to run the tests](#how-to-run-the-tests)
  - [With coverage and data race detection](#with-coverage-and-data-race-detection)
- [Future work / Improvements](#future-work--improvements)

## Planning

| Task Description | Estimated Time |
| :--- | :--- |
| Reading instructions & planning | 15 min |
| Designing architecture & interfaces | 1 Hour |
| Implementing key creation, storage, and API endpoints | 30 min |
| Implementing AES-GCM encryption/decryption & audit logging | 1 Hour |
| Concurrency safety & error handling | 1 Hour |
| Writing unit tests | 1 Hour |
| Review and polishing | 1 Hour |
| Documentation & README | 10 min |
| **Total Estimated Time** | 6h |

## Architecture and design choices

Overall architectural division of concerns:
1. Transport layer handles protocol-specific logic (e.g., HTTP). Request parsing and response formatting live in the transport/ directory. This ensures the core logic remains protocol-agnostic
2. Transport layer acts as the entry point for business logic. It receives parsed data from the Transport layer and orchestrates the workflow
3. Service layer executes the business logic. It interacts with crypto (only for key creation) and store (key storage).
    - Both crypto and store are interfaces. Meaning it's possible to easily swith the underlying cryptographic type and key storage mechanism.
    - key storage also uses crypto for sealing and unsealing

Some additional generic design decisions and considerations:
- The key storage must support concurrent access. Accessing a specific key should not lock the entire keystore.
- To optimize performance, concurrent access to a specific key should not require waiting for cryptographic operations to complete. The key shall be copied and unsealed, allowing the cryptographic operation to be performed outside of the exclusive lock.
- The logger shall abstract the output channel

### Project structure
```
cmd\
    keysafe\        > Keysafe main program
internal\           
    audit\          > Json Audit logging
    config\         > Configuration of web service via .env file or env vars
    crypto\         > Abstraction and realization of needed cryptographic operations
    service\        > service business logic
    store\          > Abstraction and realization of key storage
    transport\http  > Http handlers and DTO
```
By principle all go files shall have unit tests. Coverage is always measured.

## Security considerations

- We assume that the KeySafe web server code runs within a confidential computing environment.
- The KeySafe Master Key is always generated in-memory during boot. It is the only key that exists in plaintext within the service. While this is not ideal for a production environment, it is the current implementation.
- In-memory mode ensures the KeySafe is always unsealed by default during boot.
- All customer keys are short-lived in memory in plaintext format only when performing a data encryption/decryption operation. Explicit wiping is performed manually, without relying on Golang Garbage Collection. This reduces the attack vector to a tiny instance
- All key material in the keystore is sealed by a Master Key. Keys never exist in plaintext within persistent storage

## Run the service
```
go mod tidy
go run cmd/keysafe/main.go
```

There are two ways to configure the service, either by changing the `.env` file, or by directly passing an env variable. e.g.:
```
MAX_KEY_STORAGE=100 go run cmd/keysafe/main.go
```
Env vars always overwrite the .env definition.

### Smoke test the service
Terminal 1: Launch the keysafe webservice
```
go run cmd/keysafe/main.go
```

Terminal 2: Execute the smoke test script
```
bash script/smoke_test.sh
```

#### Expected results
Terminal 1:
```
Configuration:
{
  "KEY_STORAGE": "in-memory",
  "MAX_KEY_STORAGE": 100,
  "LISTEN_ADDRESS": ":8000"
}
Setting up 'in-memory' Keystorage
Master key installed. Vault unsealed.
Key store initialized
KeySafe Service initialized
Audit Logger initialized
HTTP Server started at :8000
```
Terminal 2:
```
1. Creating Key: 
{
  "key_id": "231ac48c-53be-45a7-92ea-58ef9d2cd6b3"
}
2. Listing keys: 
{
  "keys": [
    "231ac48c-53be-45a7-92ea-58ef9d2cd6b3"
  ]
}
3. Encrypting Data: 
Some Test!
{
  "ciphertext": "oiLJnqchbvyyPiO+2LkxgFWTTUvb/DnfeABUvvGPUD8tYcnCTTw="
}
4. Decrypting Data: 
{
  "plaintext": "U29tZSBUZXN0IQ=="
}
Some Test!
```
## Run the tests
```
go mod tidy
go test -count=1 ./...
```

### Coverage and data race detection
#### Verbose
```
go test -coverprofile=code_coverage.out -v -count=1 -race ./...
```
#### Silent
```
go test -coverprofile=code_coverage.out -count=1 -race ./...
```

## Future work / Improvements
- Bring code coverage up to 100%. Currently, due to time constraints is around ~80%
- Implement authentication
- Implement Shamir Secret Key to seal the vault. On first execution shares are printed. Later it's required to unlock the vault
- Run this service with Confidential Computing Environment
- Containerize web-service with docker
- Generate OpenAPI documentation
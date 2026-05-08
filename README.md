# Enclaive Coding Challenge 2

## Table of contents

## Planning

| Task Description | Estimated Time |
| :--- | :--- |
| Reading instructions & planning | 15 min |
| Designing architecture & interfaces | 1 Hour |
| Implementing key creation, storage, and API endpoints | 30 min |
| Implementing AES-GCM encryption/decryption & audit logging | 1 Hour |
| Concurrency safety & error handling | 1 Hour |
| Writing unit tests | 1 Hour |
| Documentation & README | 10 min |
| **Total Estimated Time** | 5h |

## Architecture and design choices

- All key material in the keystore shall be sealed by a Master Key. The key shall never exist in plaintext in storage.



### Project structure
```
cmd\
    keysafe\        > Keysafe main program
internal\           
    config\         > Env. variables configurations (if any)
    audit\          > log and audit
    crypto\         > Abstraction and realization of needed cryptographic operations
    handlers\       > service handlers
    store\          > Abstraction and realization of key storage
    transport\http  > web server
doc\                > OpenAPI
```
By principle all go files shall have unit tests. Coverage shall be measured always

## Security considerations

- We consider that the keysafe webserver code runs in a confidential computing environment.

## How to run the service

## How to run the tests

## Future work / Improvements

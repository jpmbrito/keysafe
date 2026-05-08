#!/bin/bash
set -e

BASE_URL="http://localhost:8000"
PLAINTEXT="Some Test!"
B64_DATA=$(echo -n "$PLAINTEXT" | base64)

echo "1. Creating Key: "
NEW_KEY_JSON=$(curl -s -X POST "$BASE_URL/keys" \
    -H "Content-Type: application/json" \
    -d '{"name": "test-key-01"}')

echo $NEW_KEY_JSON | jq '.'
KEY_ID=$(echo $NEW_KEY_JSON | jq -r '.key_id')

echo "2. Listing keys: "
KEYS_JSON=$(curl -s -X GET "$BASE_URL/keys")
echo $KEYS_JSON | jq '.'

echo "3. Encrypting Data: "
echo $PLAINTEXT
ENCRYPT_JSON=$(curl -s -X POST "$BASE_URL/encrypt" \
    -H "Content-Type: application/json" \
    -d "{
        \"key_id\": \"$KEY_ID\",
        \"plaintext\": \"$B64_DATA\"
    }")

echo $ENCRYPT_JSON | jq '.'
CIPHERTEXT=$(echo $ENCRYPT_JSON | jq -r '.ciphertext')

echo "4. Decrypting Data: "
DECRYPT_JSON=$(curl -s -X POST "$BASE_URL/decrypt" \
    -H "Content-Type: application/json" \
    -d "{
        \"key_id\": \"$KEY_ID\",
        \"ciphertext\": \"$CIPHERTEXT\"
    }")

echo $DECRYPT_JSON | jq '.'
RESULT_B64=$(echo $DECRYPT_JSON | jq -r '.plaintext')
DECRYPTED_TEXT=$(echo "$RESULT_B64" | base64 -d)
echo $DECRYPTED_TEXT
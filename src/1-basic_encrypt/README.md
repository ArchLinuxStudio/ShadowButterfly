# ShadowButterfly

Basic version with a rough AEAD encrypt.

## client send request

CIPHER_LENGTH(4 bytes string) + IV_LENGTH(64) + ADD_LENGTH(64) + TAG_LENGTH(16) + CIPHER(IT DEPENDS)

## server send back data to client

CIPHER_LENGTH(4 bytes string) + TAG_LENGTH(16) + CIPHER(IT DEPENDS)

CIPHER_LENGTH(4 bytes string): default BUFSIZ is 8192, so 4 bytes is enough.

## key

you can use `openssl rand -base64 24` to get a 32 bytes strong password.

The key length should match the encryption method, you can change them if you want.

- MBEDTLS_CIPHER_AES_256_GCM: use 32 bytes key
- MBEDTLS_CIPHER_AES_192_GCM: use 24 bytes key
- MBEDTLS_CIPHER_AES_128_GCM: use 16 bytes key

## usage

```bash
gcc loop_client.c -lmbedcrypto
gcc loop_server.c -lmbedcrypto -o b.out
```

## process

client:

1. init IV and ADD
2. wait for input
3. encrypt the input
4. assemble and send data to server

server:

5. parse data send by client. server and client share IV and ADD now.
6. decrypt data, get the plain text: address
7. request target address
8. encrypt received data
9. assemble and send data to client

client:

10. parse data send by server.
11. decrypt data, get the plain text: desired data

---

CIPHER, TAG, IV,ADD may contain `0x00`, so you should not use function like strcat or strlen, these function would "cut the string" prematurely when they met `0x00`, you should use functions like memcpy instead.

And because of this, when you transfer data between server and client, the cipher may contain `0x00`, so you should also append the cipher length, in this way, the server or client will know how long the cipher is. IV\ADD\TAG's length is fixed, so don't need to pass their length.

# ShadowButterfly

Basic HTTP tunnel sample with encryption for browser and other client program.

## client send request

> For AEAD modes, the tag will be appended to the ciphertext, as recommended by RFC 5116.

CIPHER_LENGTH actually contain the cipher length and tag length.

First, client share IV and ADD with server:

IV_LENGTH(64) + ADD_LENGTH(64)

Subsequently, client can send cipeher directly:

CIPHER_LENGTH(5 bytes string) + CIPHER(IT DEPENDS)

## server send back data to client

First, server parse IV and ADD received from client:

IV_LENGTH(64) + ADD_LENGTH(64)

Subsequently, server can send cipeher directly:

CIPHER_LENGTH(5 bytes string) + CIPHER(IT DEPENDS)

## usage

```bash
gcc loop_client.c -lmbedcrypto
gcc loop_server.c -o b.out -lmbedcrypto
```

## process

client:

1. start local server
2. accept browser request
3. fork a child process to deal with the request
4. create_connect with remote server
5. send 200 OK to browser
6. deal with the request, fork other two child process to forward data between client and server with encryption and decryption

server:

1. start local server
2. accept client request
3. fork a child process to deal with the request
4. read and parse header first
5. create_connect with target server
6. deal with the request, fork other two child process to forward data between client and server with encryption and decryption

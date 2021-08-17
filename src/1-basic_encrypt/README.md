# ShadowButterfly

Basic version with a rough AEAD encrypt.

## client send request

CIPHER_LENGTH(4 bytes string) + IV_LENGTH(64) + ADD_LENGTH(64) + TAG_LENGTH(16) + CIPHER(IT DEPENDS)

## server send back data to client

CIPHER_LENGTH(4 bytes string) + TAG_LENGTH(16) + CIPHER(IT DEPENDS)

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

---

CIPHER_LENGTH(4 bytes string): default BUFSIZ is 8192, so 4 bytes is enough.

CIPHER, TAG, IV,ADD 等中可能存在 0x00, 这样用 strcat strlen 等会有问题，如遇到会提前截断。用 memcpy 之类的替代。由于此，服务器以及客户端在互相传递加密数据时可能存在 0x00,所以也要同时附上密文的长度，以便通信的对方确定应该读取密文的长度是多少。对于 IV ADD 以及 TAG 在本实现中均为固定程度 所以在两端传输数据时,这些字段可不传长度

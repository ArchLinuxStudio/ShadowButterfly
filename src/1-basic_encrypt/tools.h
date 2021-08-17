#include "tools.c"


int ctr_drbg_random(int length, unsigned char *random_num);

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length,
                    mbedtls_cipher_context_t ctx);

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add, unsigned char *tag,
                    unsigned char *result, mbedtls_cipher_context_t ctx);

void dump_buf(char *info, uint8_t *buf, uint32_t len);
#include <string.h>

#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>

#define IV_LENGTH 64
#define ADD_LENGTH 64
#define TAG_LENGTH 16
#define CIPHER_LENGTH 4

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 6789

#define KEY "qdEDMtTtJviT/o3V2fa2hKm0+00lT9/1"

int ctr_drbg_random(int length, unsigned char *random_num) {
  int ret = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  char pers[] = "CTR_DRBG";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));

  ret = mbedtls_ctr_drbg_random(&ctr_drbg, random_num, length);

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add, unsigned char *tag,
                    unsigned char *result, mbedtls_cipher_context_t *ctx) {

  size_t result_len = 0;

  mbedtls_cipher_setkey(ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_DECRYPT);

  int ret = mbedtls_cipher_auth_decrypt_ext(ctx, iv, IV_LENGTH, add, ADD_LENGTH,
                                            input, input_length, result, BUFSIZ,
                                            &result_len, TAG_LENGTH);

  return ret;
}

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *ret_cipher, int *length,
                    mbedtls_cipher_context_t *ctx) {
  int ret;
  size_t len;
  mbedtls_cipher_setkey(ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_ENCRYPT);
  ret = mbedtls_cipher_auth_encrypt_ext(
      ctx, iv, IV_LENGTH, add, ADD_LENGTH, (const unsigned char *)input,
      strlen(input), ret_cipher, BUFSIZ, &len, TAG_LENGTH);
  *length = len;
  return ret;
}

void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}

int init_cipher_context(mbedtls_cipher_context_t *ctx,
                        mbedtls_cipher_type_t type) {
  int ret;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(ctx);
  info = mbedtls_cipher_info_from_type(type);
  ret = mbedtls_cipher_setup(ctx, info);

  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(ctx),
                 mbedtls_cipher_get_block_size(ctx));
  return ret;
}
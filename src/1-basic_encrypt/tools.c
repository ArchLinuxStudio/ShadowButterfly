#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
  unsigned char *random = malloc(sizeof(char) * length);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  char pers[] = "CTR_DRBG";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));

  ret = mbedtls_ctr_drbg_random(&ctr_drbg, random, length);
  if (ret != 0) {
    fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
            ret);
    return ret;
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  memcpy(random_num, random, length);
  free(random);

  return ret;
}

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add, unsigned char *tag,
                    unsigned char *result, mbedtls_cipher_context_t ctx) {

  unsigned char *decrypt_result = malloc(sizeof(char) * input_length);
  memset(decrypt_result, 0, input_length);
  size_t result_len = 0;

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_DECRYPT);

  int ret = mbedtls_cipher_auth_decrypt(&ctx, iv, IV_LENGTH, add, ADD_LENGTH,
                                        input, input_length, decrypt_result,
                                        &result_len, tag, TAG_LENGTH);

  if (ret != 0) {
    printf("\n-------------------seems something wrong: ret %d\n", ret);
  }

  memcpy(result, decrypt_result, result_len);

  free(decrypt_result);
  decrypt_result = NULL;
  return ret;
}

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length,
                    mbedtls_cipher_context_t ctx) {

  // TAG
  unsigned char tag_buf[TAG_LENGTH] = {0};
  // cipher
  unsigned char cipher[BUFSIZ] = {0};
  size_t len;

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_ENCRYPT);
  mbedtls_cipher_auth_encrypt(&ctx, iv, IV_LENGTH, add, ADD_LENGTH,
                              (const unsigned char *)input, strlen(input),
                              cipher, &len, tag_buf, TAG_LENGTH);

  printf("encrypt:");
  for (int i = 0; i < len; i++) {
    char str[3];
    sprintf(str, "%02x", (int)cipher[i]);
    printf("%s", str);
  }
  printf("\ntag:");
  for (int i = 0; i < TAG_LENGTH; i++) {
    char str[3];
    sprintf(str, "%02x", (int)tag_buf[i]);
    printf("%s", str);
  }

  memcpy(tag, tag_buf, TAG_LENGTH);
  memcpy(ret_cipher, cipher, len);

  *length = len;

  return 0;
}

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}
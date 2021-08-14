#include <arpa/inet.h>
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

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}

unsigned char *ctr_drbg_random(int length);

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length);

unsigned char *decrypt_aes_gcm(int length);

int main() {
  // initiate struct sockaddr_in of the server (specific IP and port)
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET; // ipv4
  serv_addr.sin_addr.s_addr =
      inet_addr("127.0.0.1");       // change to your server ip
  serv_addr.sin_port = htons(6789); // change to your server port

  char buf_send[BUFSIZ] = {0}; // send request web page buffer
  char buf_recv[BUFSIZ] = {0}; // receive response buffer

  // get timestamp
  time_t timestamp = time(NULL);
  // set key
  char *key = "abcdefghijklmnop";
  while (1) {

    // init IV
    unsigned char *IV = ctr_drbg_random(64);
    dump_buf("\n  . generate 64 byte random data:IV ... ok", IV, 64);

    // init ADD
    unsigned char *ADD = ctr_drbg_random(64);
    dump_buf("\n  . generate 64 byte random data:ADD ... ok", ADD, 64);

    // create socket
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1)
      return -1;

    // get the string entered by the user and
    printf("Input a string: ");
    fgets(buf_send, BUFSIZ, stdin);
    // trim \n
    buf_send[strlen(buf_send) - 1] = 0;

    unsigned char *tag;
    unsigned char *cipher;
    tag = malloc(sizeof(char) * 16);
    cipher = malloc(sizeof(char) * BUFSIZ);
    int length = 0;

    // encrypt request website address
    encrypt_aes_gcm(key, buf_send, IV, ADD, tag, cipher, &length);

    // printf("encrypt:");
    // for (int i = 0; i < length; i++) {
    //   char str[3];
    //   sprintf(str, "%02x", (cipher[i]));
    //   printf("%s", str);
    // }
    // printf("\ntag:");
    // for (int i = 0; i < 16; i++) {
    //   char str[3];
    //   sprintf(str, "%02x", tag[i]);
    //   printf("%s", str);
    // }
    dump_buf("\n  . get 16 byte :TAG ... ok", tag, 16);
    dump_buf("\n  . get data:CIPHER ... ok", cipher, strlen((char *)cipher));

    // append IV and ADD
    memset(buf_send, 0, BUFSIZ);
    strcat(buf_send, (char *)IV);
    strcat(buf_send, (char *)ADD);
    // append TAG
    strcat(buf_send, (char *)tag);

    // // append cipher
    strcat(buf_send, (char *)cipher);

    dump_buf("\n  . buffend send: ... ok", (unsigned char *)buf_send,
             strlen(buf_send));

    // send all data to the server
    send(serv_sock, buf_send, strlen(buf_send), 0);

    // do {
    //   memset(buf_recv, 0, sizeof(buf_recv));
    //   // receive the data returned by the server
    //   int ret = recv(serv_sock, buf_recv, sizeof(buf_recv) - 1, 0);
    //   if (ret <= 0) {
    //     printf("failed\n  ! read finished %d\n\n", ret);
    //     break;
    //   }
    //   // only print in this example
    //   printf("\n\n%lu bytes readed\n\n", strlen(buf_recv));
    //   printf("\n\nMessage form server: %s\n\n", buf_recv);

    // } while (1);

    memset(buf_send, 0, BUFSIZ); // reset buf
    memset(buf_recv, 0, BUFSIZ);
    close(serv_sock);
  }

  return 0;
}

unsigned char *ctr_drbg_random(int length) {
  int ret = 0;
  unsigned char *random = malloc(sizeof(char) * length);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  char pers[] = "CTR_DRBG";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));

  mbedtls_printf("\n  . setup rng ... ok\n");

  do {
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, random, length);
    printf("\n\nret:%d\n\n", ret);

    printf("\n\nstrlen(random):%lu\n\n", strlen((char *)random));

  } while (strlen((char *)random) < length);

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return random;
}

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length) {

  // TAG
  unsigned char tag_buf[16] = {0};
  // cipher
  unsigned char cipher[BUFSIZ] = {0};
  size_t len;

  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(&ctx);
  info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
  mbedtls_cipher_setup(&ctx, info);
  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(&ctx),
                 mbedtls_cipher_get_block_size(&ctx));

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_ENCRYPT);
  mbedtls_cipher_auth_encrypt(&ctx, iv, strlen((char *)iv), add,
                              strlen((char *)add), (const unsigned char *)input,
                              strlen(input), cipher, &len, tag_buf, 16);

  printf("encrypt:");
  for (int i = 0; i < len; i++) {
    char str[3];
    sprintf(str, "%02x", (int)cipher[i]);
    printf("%s", str);
  }
  printf("\ntag:");
  for (int i = 0; i < 16; i++) {
    char str[3];
    sprintf(str, "%02x", (int)tag_buf[i]);
    printf("%s", str);
  }

  memcpy(tag, tag_buf, 16);
  memcpy(ret_cipher, cipher, len);
  *length = len;

  return 0;
}
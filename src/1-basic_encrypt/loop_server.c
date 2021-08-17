#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define REQUEST_SERVER_PORT 80

#define KEY "qdEDMtTtJviT/o3V2fa2hKm0+00lT9/1"
#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 6789

#define IV_LENGTH 64
#define ADD_LENGTH 64
#define TAG_LENGTH 16
#define CIPHER_LENGTH 4

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}

int parse_client_request(unsigned char *buffer, unsigned char *IV,
                         unsigned char *ADD, unsigned char *cipher,
                         int *cipher_length, unsigned char *tag);

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add, unsigned char *tag,
                    unsigned char *result);

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length);

int main() {
  // init socket
  int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind & setsockopt
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr =
      inet_addr(SERVER_ADDRESS); // change to your server ip. loopback address
                                 // cannot be used online
  serv_addr.sin_port = htons(SERVER_PORT); // change to your server port.
  int reuse = 1;
  if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) ==
      -1) {
    printf("error!%s", strerror(errno));
    close(serv_sock);
    return -1;
  }

  if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    printf("error!%s", strerror(errno));
    close(serv_sock);
    return -1;
  }

  // listen
  listen(serv_sock, SOMAXCONN);

  // accept client request
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size = sizeof(clnt_addr);
  // buffer to accept client message
  unsigned char buffer[BUFSIZ] = {0};
  // main loop
  while (1) {
    // accept
    int clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    read(clnt_sock, buffer,
         sizeof(buffer) - 1); // read client data

    // parse client request
    unsigned char *IV;
    unsigned char *ADD;
    unsigned char *cipher;
    int cipher_length = 0;
    unsigned char *tag;
    unsigned char *result;
    tag = malloc(sizeof(char) * TAG_LENGTH);
    ADD = malloc(sizeof(char) * ADD_LENGTH);
    IV = malloc(sizeof(char) * IV_LENGTH);
    cipher = malloc(sizeof(char) * BUFSIZ);

    parse_client_request(buffer, IV, ADD, cipher, &cipher_length, tag);

    printf("\n  . CIPHER LENGTH:-------- %d", cipher_length);
    dump_buf("\n  . IV:--------", IV, IV_LENGTH);
    dump_buf("\n  . ADD:--------", ADD, ADD_LENGTH);
    dump_buf("\n  . tag:--------", tag, TAG_LENGTH);
    dump_buf("\n  . cipher:--------", cipher, cipher_length);

    result = malloc(sizeof(char) * cipher_length);

    // decrypt the ciphet to get address
    char *SERVER_NAME;
    if (decrypt_aes_gcm(KEY, cipher, cipher_length, IV, ADD, tag, result)) {
      // auth failed
      // terminate connection immediately
      close(clnt_sock);
      close(serv_sock);
      return 0;
    }

    printf("\n\n\n%s\n\n\n", result);
    SERVER_NAME = (char *)result;

    int request_server_fd;
    // buffer to send request and accept target server response
    char server_use_buf[BUFSIZ];
    struct sockaddr_in request_server_addr;
    struct hostent *request_server_host;

    int ret = 0;
    int len = 0;
    int total_response_len = 0;
    /*
     * start the connection
     * gethostbyname & make socket & connect
     */
    printf("\n  . Connecting to tcp/%s/%4d...", SERVER_NAME,
           REQUEST_SERVER_PORT);
    fflush(stdout);

    if ((request_server_host = gethostbyname(SERVER_NAME)) == NULL) {
      printf(" failed\n  ! gethostbyname failed\n\n");
      return -1;
    }

    if ((request_server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
      printf(" failed\n  ! socket returned %d\n\n", request_server_fd);
      return -1;
    }

    memcpy((void *)&request_server_addr.sin_addr,
           (void *)request_server_host->h_addr, request_server_host->h_length);

    request_server_addr.sin_family = AF_INET;
    request_server_addr.sin_port = htons(REQUEST_SERVER_PORT);

    if ((ret =
             connect(request_server_fd, (struct sockaddr *)&request_server_addr,
                     sizeof(request_server_addr))) < 0) {
      printf(" failed\n  ! connect returned %d\n\n", ret);
      return -1;
    }

    printf("connect to %s ok\n", SERVER_NAME);

    /*
     * send GET request to target server
     */
    printf("  > Write to server: %s", SERVER_NAME);
    fflush(stdout);

    len = sprintf(server_use_buf, GET_REQUEST);

    while ((ret = write(request_server_fd, server_use_buf, len)) <= 0) {
      if (ret != 0) {
        printf(" failed\n  ! write returned %d\n\n", ret);
        return -1;
      }
    }

    len = ret;
    printf(" %d bytes written\n\n%s", len, server_use_buf);

    /*
     * read target server response and send back to client
     */

    printf("  < Read from server: %s", SERVER_NAME);
    fflush(stdout);
    do {
      // the 16 is subtracted to reserve space for the tag
      // the 4 is subtracted to reserve space for the cipher length
      len = sizeof(server_use_buf) - 1 - CIPHER_LENGTH - TAG_LENGTH;
      memset(server_use_buf, 0, sizeof(server_use_buf));
      ret = read(request_server_fd, server_use_buf, len);

      if (ret <= 0) {
        printf("\n\nsend complete or error %d\n\n", ret);
        break;
      }

      len = ret;
      total_response_len += len;
      printf(" %d bytes read\n\n%s", len, server_use_buf);
      // send back to client
      // encrypt the data of send back to client
      unsigned char *encrypt_tag;
      unsigned char *encrypt_cipher;
      encrypt_tag = malloc(sizeof(char) * TAG_LENGTH);
      encrypt_cipher = malloc(sizeof(char) * BUFSIZ);
      memset(encrypt_tag, 0, TAG_LENGTH);
      memset(encrypt_cipher, 0, BUFSIZ);

      int length;

      // cipher or tag may contains '00'
      // so should not use strlen
      dump_buf("\n  . encrypt used IV :--------", IV, IV_LENGTH);
      dump_buf("\n  . encrypt used ADD  :--------", ADD, ADD_LENGTH);
      printf("\nencrypt used KEY \n%s", KEY);
      encrypt_aes_gcm(KEY, server_use_buf, IV, ADD, encrypt_tag, encrypt_cipher,
                      &length);

      printf("\n\nreturn cipher length: %d\n\n", length);
      memset(server_use_buf, 0, BUFSIZ);

      // append cipher length
      char *length_buffer = malloc(sizeof(char) * CIPHER_LENGTH);
      memset(length_buffer, 0, CIPHER_LENGTH);
      sprintf(length_buffer, "%d", length);
      memcpy(server_use_buf, length_buffer, CIPHER_LENGTH);
      dump_buf("\n  . cipher length :--------", (unsigned char *)server_use_buf,
               CIPHER_LENGTH);

      // append tag
      memcpy(server_use_buf + CIPHER_LENGTH, encrypt_tag, TAG_LENGTH);
      dump_buf("\n  . add tag :--------", (unsigned char *)server_use_buf,
               CIPHER_LENGTH + TAG_LENGTH);

      // append cipher
      memcpy(server_use_buf + CIPHER_LENGTH + TAG_LENGTH, encrypt_cipher,
             length);
      dump_buf("\n  . add encrypt_cipher :--------",
               (unsigned char *)server_use_buf,
               CIPHER_LENGTH + TAG_LENGTH + length);

      write(clnt_sock, server_use_buf, CIPHER_LENGTH + TAG_LENGTH + length);

    } while (1);

    printf("\n\n\n\n\nget %d bytes\n", total_response_len);

    close(request_server_fd);
    close(clnt_sock);
    memset(buffer, 0, BUFSIZ);
  }

  close(serv_sock);

  return 0;
}

int parse_client_request(unsigned char *buffer, unsigned char *IV,
                         unsigned char *ADD, unsigned char *cipher,
                         int *cipher_length, unsigned char *tag) {

  char *length_buffer = malloc(sizeof(char) * CIPHER_LENGTH);
  memcpy(length_buffer, buffer, CIPHER_LENGTH);
  int len = atoi(length_buffer);
  printf("\nreceive client cipher length : %d\n\n", len);

  *cipher_length = len;
  memcpy(IV, buffer + CIPHER_LENGTH, IV_LENGTH);
  memcpy(ADD, buffer + CIPHER_LENGTH + IV_LENGTH, ADD_LENGTH);
  memcpy(tag, buffer + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, TAG_LENGTH);
  memcpy(cipher, buffer + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + TAG_LENGTH,
         len);
  return 0;
}

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add, unsigned char *tag,
                    unsigned char *result) {

  unsigned char *decrypt_result = malloc(sizeof(char) * input_length);

  size_t result_len = 0;

  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(&ctx);
  info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
  mbedtls_cipher_setup(&ctx, info);
  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(&ctx),
                 mbedtls_cipher_get_block_size(&ctx));

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_DECRYPT);

  int ret = mbedtls_cipher_auth_decrypt(
      &ctx, (const unsigned char *)iv, IV_LENGTH, (const unsigned char *)add,
      ADD_LENGTH, input, input_length, decrypt_result, &result_len, tag,
      TAG_LENGTH);

  memcpy(result, decrypt_result, result_len);

  free(decrypt_result);
  mbedtls_cipher_free(&ctx);
  return ret;
}

int encrypt_aes_gcm(char *key, char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *ret_cipher, int *length) {

  unsigned char *tag_buf = malloc(sizeof(char) * TAG_LENGTH);
  unsigned char *cipher = malloc(sizeof(char) * BUFSIZ);

  size_t len;

  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(&ctx);
  info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
  mbedtls_cipher_setup(&ctx, info);
  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(&ctx),
                 mbedtls_cipher_get_block_size(&ctx));

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_ENCRYPT);
  mbedtls_cipher_auth_encrypt(&ctx, iv, strlen((char *)iv), add,
                              strlen((char *)add), (const unsigned char *)input,
                              strlen(input), cipher, &len, tag_buf, TAG_LENGTH);

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

  printf("\n\ncipher length %zu\n\n", len);

  memcpy(tag, tag_buf, TAG_LENGTH);
  memcpy(ret_cipher, cipher, len);

  *length = len;
  mbedtls_cipher_free(&ctx);

  return 0;
}
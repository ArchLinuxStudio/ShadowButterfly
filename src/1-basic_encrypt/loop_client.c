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

#include "tools.h"

int parse_server_send_back(unsigned char *buffer, unsigned char *cipher,
                           int *cipher_length, unsigned char *tag);

int main() {
  // initiate struct sockaddr_in of the server (specific IP and port)
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET; // ipv4
  serv_addr.sin_addr.s_addr =
      inet_addr(SERVER_ADDRESS);           // change to your server ip
  serv_addr.sin_port = htons(SERVER_PORT); // change to your server port

  char buf_send[BUFSIZ] = {0}; // send request web page buffer
  char buf_recv[BUFSIZ] = {0}; // receive response buffer

  mbedtls_cipher_context_t *ctx;
  const mbedtls_cipher_info_t *info;

  while (1) {
    ctx = malloc(sizeof(mbedtls_cipher_context_t));
    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));

    mbedtls_cipher_init(ctx);
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
    mbedtls_cipher_setup(ctx, info);

    mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                   mbedtls_cipher_get_name(ctx),
                   mbedtls_cipher_get_block_size(ctx));

    int ret;

    // init IV
    unsigned char IV[IV_LENGTH] = {0};
    ret = ctr_drbg_random(IV_LENGTH, IV);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }
    // dump_buf("\n  . generate 64 byte random data:IV ... ok", IV, IV_LENGTH);

    // init ADD
    unsigned char ADD[ADD_LENGTH] = {0};
    ret = ctr_drbg_random(ADD_LENGTH, ADD);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }
    // dump_buf("\n  . generate 64 byte random data:ADD ... ok", ADD,
    // ADD_LENGTH);

    // create socket
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1)
      return -1;

    // get the string entered by the user
    printf("Input a website address: ");
    fgets(buf_send, BUFSIZ, stdin);
    // trim \n
    buf_send[strlen(buf_send) - 1] = 0;

    unsigned char *tag;
    unsigned char *cipher;
    tag = malloc(sizeof(char) * TAG_LENGTH);
    memset(tag, 0, TAG_LENGTH);
    cipher = malloc(sizeof(char) * BUFSIZ);
    memset(cipher, 0, BUFSIZ);
    int length = 0;

    // encrypt request website address
    encrypt_aes_gcm(KEY, buf_send, IV, ADD, tag, cipher, &length, ctx);

    memset(buf_send, 0, BUFSIZ);

    // append cipher length
    char *length_buffer = malloc(sizeof(char) * CIPHER_LENGTH);
    memset(length_buffer, 0, CIPHER_LENGTH);
    sprintf(length_buffer, "%d", length);
    memcpy(buf_send, length_buffer, CIPHER_LENGTH);

    // append IV and ADD
    memcpy(buf_send + CIPHER_LENGTH, IV, IV_LENGTH);
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH, ADD, ADD_LENGTH);

    // append TAG
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, tag, TAG_LENGTH);

    // append cipher
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + TAG_LENGTH,
           cipher, length);

    // dump_buf("\n  . buffend send: ... ok", (unsigned char *)buf_send,
    //          CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + TAG_LENGTH + length);

    // send all data to the server
    send(serv_sock, buf_send,
         CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + TAG_LENGTH + length, 0);

    // clean up
    free(tag);
    tag = NULL;
    free(cipher);
    cipher = NULL;
    free(length_buffer);
    length_buffer = NULL;

    do {
      memset(buf_recv, 0, sizeof(buf_recv));
      // receive the data returned by the server
      int ret = recv(serv_sock, buf_recv, sizeof(buf_recv) - 1, 0);
      if (ret <= 0) {
        printf("\n read finished or error: %d\n\n", ret);
        break;
      }

      // decrypt
      unsigned char *decrypt_result;
      decrypt_result = malloc(sizeof(char) * BUFSIZ);
      unsigned char *decrypt_cipher;
      unsigned char *decrypt_tag;
      decrypt_tag = malloc(sizeof(char) * TAG_LENGTH);
      decrypt_cipher = malloc(sizeof(char) * BUFSIZ);
      memset(decrypt_result, 0, BUFSIZ);
      memset(decrypt_cipher, 0, BUFSIZ);
      memset(decrypt_tag, 0, TAG_LENGTH);

      int cipher_length = 0;

      parse_server_send_back((unsigned char *)buf_recv, decrypt_cipher,
                             &cipher_length, decrypt_tag);

      printf("\nparse received data.....contains cipher length : %d\n",
             cipher_length);

      dump_buf("\n  . tag :--------", decrypt_tag, TAG_LENGTH);
      dump_buf("\n  . decrypt_cipher :--------", decrypt_cipher, cipher_length);

      if (decrypt_aes_gcm(KEY, decrypt_cipher, cipher_length, IV, ADD,
                          decrypt_tag, decrypt_result, ctx)) {
        // auth failed
        // terminate connection immediately
        close(serv_sock);
        return 0;
      }
      // only print in this example
      printf("\n\n%d bytes readed\n\n", cipher_length);
      printf("\n\nMessage form server: %s\n\n", decrypt_result);

      free(decrypt_result);
      decrypt_result = NULL;
      free(decrypt_tag);
      decrypt_tag = NULL;
      free(decrypt_cipher);
      decrypt_cipher = NULL;

    } while (1);

    memset(buf_send, 0, BUFSIZ); // reset buf
    memset(buf_recv, 0, BUFSIZ);
    mbedtls_cipher_free(ctx);
    free(ctx);
    ctx = NULL;
    close(serv_sock);
  }

  return 0;
}

int parse_server_send_back(unsigned char *buffer, unsigned char *cipher,
                           int *cipher_length, unsigned char *tag) {
  char *length_buffer = malloc(sizeof(char) * CIPHER_LENGTH);
  memcpy(length_buffer, buffer, CIPHER_LENGTH);
  int len = atoi(length_buffer);

  *cipher_length = len;
  memcpy(tag, buffer + CIPHER_LENGTH, TAG_LENGTH);
  memcpy(cipher, buffer + CIPHER_LENGTH + TAG_LENGTH, len);

  free(length_buffer);
  length_buffer = NULL;
  return 0;
}
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

/**
 * \brief               This function parse the proxy server's feedback.
 *
 * \param buffer        Proxy server's send back data.
 * \param cipher        Used to store parsed ciphertext data.
 * \param cipher_length \p cipher length.
 * \param tag           Used to store parsed tag data.
 *
 * \return              \c 0 on success.
 */
int parse_server_send_back(unsigned char *buffer, unsigned char *cipher,
                           int *cipher_length);

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

  while (1) {
    int ret;

    ctx = malloc(sizeof(mbedtls_cipher_context_t));
    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));

    ret = init_cipher_context(ctx, MBEDTLS_CIPHER_AES_256_GCM);
    if (ret != 0) {
      fprintf(stderr, "init_cipher_context error! : %d \n", ret);
      return ret;
    }

    // init IV
    unsigned char IV[IV_LENGTH] = {0};
    ret = ctr_drbg_random(IV_LENGTH, IV);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }
    dump_buf("\n  . generate 64 byte random data:IV ... ok", IV, IV_LENGTH);

    // init ADD
    unsigned char ADD[ADD_LENGTH] = {0};
    ret = ctr_drbg_random(ADD_LENGTH, ADD);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }
    dump_buf("\n  . generate 64 byte random data:ADD ... ok", ADD, ADD_LENGTH);

    // create socket
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1)
      return -1;

    // get the string entered by the user
    printf("Input a website address: ");
    fgets(buf_send, BUFSIZ - IV_LENGTH - ADD_LENGTH - CIPHER_LENGTH, stdin);
    // trim \n
    buf_send[strlen(buf_send) - 1] = 0;

    // unsigned char tag[TAG_LENGTH] = {0};
    unsigned char cipher[BUFSIZ] = {0};
    int length = 0;

    // encrypt request website address
    ret = encrypt_aes_gcm(KEY, buf_send, IV, ADD, cipher, &length, ctx);
    if (ret != 0) {
      fprintf(stderr, "encrypt failed: %d \n", ret);
      return ret;
    }
    // dump_buf("\n  . tag: ... ok", tag, TAG_LENGTH);
    dump_buf("\n  . cipher: ... ok", cipher, length);

    memset(buf_send, 0, BUFSIZ);

    // append cipher length
    char length_buffer[CIPHER_LENGTH] = {0};
    sprintf(length_buffer, "%d", length);
    memcpy(buf_send, length_buffer, CIPHER_LENGTH);

    // append IV and ADD
    memcpy(buf_send + CIPHER_LENGTH, IV, IV_LENGTH);
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH, ADD, ADD_LENGTH);

    // append TAG
    // memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, tag,
    // TAG_LENGTH);

    // append cipher
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, cipher, length);

    dump_buf("\n  . buffend send: ... ok", (unsigned char *)buf_send,
             CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + length);

    // send all data to the server
    send(serv_sock, buf_send, CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + length,
         0);

    do {
      memset(buf_recv, 0, sizeof(buf_recv));

      // receive the data returned by the server
      int ret = recv(serv_sock, buf_recv, sizeof(buf_recv) - 1, 0);
      if (ret <= 0) {
        printf("\n read finished or error: %d\n\n", ret);
        break;
      }

      // decrypt
      unsigned char decrypt_result[BUFSIZ] = {0};
      unsigned char decrypt_cipher[BUFSIZ] = {0};

      int cipher_length = 0;

      parse_server_send_back((unsigned char *)buf_recv, decrypt_cipher,
                             &cipher_length);

      if (decrypt_aes_gcm(KEY, decrypt_cipher, cipher_length, IV, ADD,
                          decrypt_result, ctx)) {
        // auth failed
        // terminate connection immediately
        close(serv_sock);
        return -1;
      }
      // only print in this example
      printf("\n\n%d bytes readed(include tag)\n\n", cipher_length);
      printf("\n\nMessage form server: %s\n\n", decrypt_result);

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
                           int *cipher_length) {
  char length_buffer[CIPHER_LENGTH] = {0};
  memcpy(length_buffer, buffer, CIPHER_LENGTH);
  int len = atoi(length_buffer);

  *cipher_length = len;
  memcpy(cipher, buffer + CIPHER_LENGTH, len);

  return 0;
}
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

/**
 * \brief               This function parse the server send back data.
 *
 * \param buffer        Server's send back data.
 * \param total_length  The whole buffer length.
 *
 * \return              \c 0 on success.
 */
int loop_parse_server_send_back(char *buffer, int total_length,
                                unsigned char *iv, unsigned char *add,
                                mbedtls_cipher_context_t *ctx);

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

    mbedtls_printf("\n  ------ init cipher content......ok.\n");

    // init IV
    unsigned char IV[IV_LENGTH] = {0};
    ret = ctr_drbg_random(IV_LENGTH, IV);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }

    // init ADD
    unsigned char ADD[ADD_LENGTH] = {0};
    ret = ctr_drbg_random(ADD_LENGTH, ADD);
    if (ret != 0) {
      fprintf(stderr, "get random error! mbedtls_ctr_drbg_random return: %d \n",
              ret);
      return ret;
    }

    mbedtls_printf("\n  ------ init IV&ADD......ok.\n");

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

    unsigned char cipher[BUFSIZ] = {0};
    int length = 0;

    // encrypt request website address
    ret = encrypt_aes_gcm(KEY, buf_send, strlen(buf_send), IV, ADD, cipher,
                          &length, ctx);

    mbedtls_printf("\n  ------ encrypt user input data......ok.\n");

    memset(buf_send, 0, BUFSIZ);

    // append cipher length
    char length_buffer[CIPHER_LENGTH] = {0};
    sprintf(length_buffer, "%d", length);
    memcpy(buf_send, length_buffer, CIPHER_LENGTH);

    // append IV and ADD
    memcpy(buf_send + CIPHER_LENGTH, IV, IV_LENGTH);
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH, ADD, ADD_LENGTH);

    // append cipher
    memcpy(buf_send + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, cipher, length);

    mbedtls_printf("\n  ------ assemble all send data......ok.\n");

    // send all data to the server
    send(serv_sock, buf_send, CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH + length,
         0);

    mbedtls_printf("\n  ------ all data sent......ok.\n");

    char total_buf[TOTAL_BUF_SIZE] = {0};
    int total_length = 0;

    do {
      memset(buf_recv, 0, BUFSIZ);
      // receive the data returned by the server
      int ret = recv(serv_sock, buf_recv, BUFSIZ - 1, 0);
      if (ret <= 0) {
        mbedtls_printf("\n read finished or error: %d bytes totaly received\n",
                       total_length);
        loop_parse_server_send_back(total_buf, total_length, IV, ADD, ctx);
        break;
      }
      // store all buf to total_buf
      memcpy(total_buf + total_length, buf_recv, ret);
      total_length += ret;

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

int loop_parse_server_send_back(char *buffer, int total_length,
                                unsigned char *iv, unsigned char *add,
                                mbedtls_cipher_context_t *ctx) {

  int readed_length = 0;
  int ret = 0;
  while (readed_length < total_length) {
    // first, get the cipher length
    char length_buffer[CIPHER_LENGTH] = {0};
    memcpy(length_buffer, buffer + readed_length, CIPHER_LENGTH);
    readed_length += CIPHER_LENGTH;
    int len = atoi(length_buffer);

    // second, read the cipher
    char *cipher_buffer = malloc(sizeof(char) * len);
    memset(cipher_buffer, 0, len);
    memcpy(cipher_buffer, buffer + readed_length, len);
    readed_length += len;

    mbedtls_printf("\n  ------ parted package length: %d\n", len);
    // dump_buf("\n  . client received cipher data :--------",
    //          (unsigned char *)cipher_buffer, len);

    // decrypt
    char *decrypt_result = malloc(sizeof(char) * len);
    memset(decrypt_result, 0, len);

    ret = decrypt_aes_gcm(KEY, (unsigned char *)cipher_buffer, len, iv, add,
                          (unsigned char *)decrypt_result, ctx);

    // only print result in this sample program.
    mbedtls_printf("\n  ------ Message form server: %s\n", decrypt_result);

    free(cipher_buffer);
    cipher_buffer = NULL;
    free(decrypt_result);
    decrypt_result = NULL;
  }

  return ret;
}
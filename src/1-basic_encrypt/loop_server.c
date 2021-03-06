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

#include "tools.h"

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define REQUEST_SERVER_PORT 80

/**
 * \brief               This function parse the client's request.
 *
 * \param buffer        Client's request data.
 * \param IV            IV to be used in cryption.The value is different in each
 *                      communication.
 * \param ADD           ADD to be used in cryption.The value is different in
 *                      each communication.
 * \param cipher        Used to store cipher data.
 * \param cipher_length \p cipher length.
 *
 * \return              \c 0 on success.
 */
int parse_client_request(unsigned char *buffer, unsigned char *IV,
                         unsigned char *ADD, unsigned char *cipher,
                         int *cipher_length);

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

  mbedtls_cipher_context_t *ctx;

  // main loop
  while (1) {
    int ret = 0;

    ctx = malloc(sizeof(mbedtls_cipher_context_t));
    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));

    init_cipher_context(ctx, MBEDTLS_CIPHER_AES_256_GCM);

    // accept
    int clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    read(clnt_sock, buffer,
         sizeof(buffer) - 1); // read client data

    // parse client request
    unsigned char IV[IV_LENGTH] = {0};
    unsigned char ADD[ADD_LENGTH] = {0};
    unsigned char cipher[BUFSIZ] = {0};

    char SERVER_NAME[BUFSIZ] = {0};
    int cipher_length = 0;
    parse_client_request(buffer, IV, ADD, cipher, &cipher_length);

    // decrypt the cipher to get address
    decrypt_aes_gcm(KEY, cipher, cipher_length, IV, ADD,
                    (unsigned char *)SERVER_NAME, ctx);

    int request_server_fd;
    struct sockaddr_in request_server_addr;
    struct hostent *request_server_host;

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

    int len = 0;
    // buffer to send request and accept target server response
    char server_use_buf[TOTAL_BUF_SIZE] = {0};
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

    char total_buf[TOTAL_BUF_SIZE] = {0};
    int total_response_len = 0;
    do {
      // the 4 is subtracted to reserve space for the cipher length
      len = BUFSIZ - 1 - CIPHER_LENGTH - TAG_LENGTH;

      memset(server_use_buf, 0, TOTAL_BUF_SIZE);
      ret = read(request_server_fd, server_use_buf, len);

      if (ret <= 0) {
        printf("\n\nsend complete or error %d\n\n", ret);
        break;
      }
      printf("\n\n %d bytes read from remote server\n\n", ret);
      // store all buf to total_buf
      memcpy(total_buf + total_response_len, server_use_buf, ret);
      total_response_len += ret;

    } while (1);

    printf("\ntotally get %d bytes\n", total_response_len);

    // send back to client
    // encrypt the data of send back to client
    unsigned char encrypt_cipher[TOTAL_BUF_SIZE] = {0};

    int length = 0;

    // cipher or tag may contains '00'
    // so should not use strlen
    encrypt_aes_gcm(KEY, total_buf, total_response_len, IV, ADD, encrypt_cipher,
                    &length, ctx);

    memset(server_use_buf, 0, TOTAL_BUF_SIZE);

    // append cipher length
    char length_buffer[CIPHER_LENGTH] = {0};
    sprintf(length_buffer, "%d", length);
    memcpy(server_use_buf, length_buffer, CIPHER_LENGTH);
    dump_buf("\n  . cipher length :--------", (unsigned char *)server_use_buf,
             CIPHER_LENGTH);

    // append cipher
    memcpy(server_use_buf + CIPHER_LENGTH, encrypt_cipher, length);

    printf("\n\n %d server sent length:\n\n", CIPHER_LENGTH + length);
    dump_buf("\n  . server sent data :--------",
             (unsigned char *)server_use_buf, CIPHER_LENGTH + length);

    write(clnt_sock, server_use_buf, CIPHER_LENGTH + length);

    close(request_server_fd);
    shutdown(clnt_sock, SHUT_WR);
    recv(clnt_sock, buffer, BUFSIZ, 0);
    mbedtls_cipher_free(ctx);
    free(ctx);
    ctx = NULL;
    memset(buffer, 0, BUFSIZ);
  }

  close(serv_sock);

  return 0;
}

int parse_client_request(unsigned char *buffer, unsigned char *IV,
                         unsigned char *ADD, unsigned char *cipher,
                         int *cipher_length) {

  char length_buffer[CIPHER_LENGTH] = {0};
  memcpy(length_buffer, buffer, CIPHER_LENGTH);
  int len = atoi(length_buffer);

  *cipher_length = len;
  memcpy(IV, buffer + CIPHER_LENGTH, IV_LENGTH);
  memcpy(ADD, buffer + CIPHER_LENGTH + IV_LENGTH, ADD_LENGTH);
  memcpy(cipher, buffer + CIPHER_LENGTH + IV_LENGTH + ADD_LENGTH, len);
  return 0;
}

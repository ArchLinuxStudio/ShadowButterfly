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
#define SERVER_PORT 80

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}

int parse_client_request(unsigned char *buffer, unsigned char *IV,
                         unsigned char *ADD, unsigned char *cipher,
                         unsigned char *tag);

int decrypt_aes_gcm(char *key, unsigned char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *result);

int main() {
  // init socket
  int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind & setsockopt
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr =
      inet_addr("127.0.0.1"); // change to your server ip. loopback address
                              // cannot be used online
  serv_addr.sin_port = htons(6789); // change to your server port.
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
  char *key = "abcdefghijklmnop";

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
    unsigned char *tag;
    unsigned char *result;
    tag = malloc(sizeof(char) * 16);
    ADD = malloc(sizeof(char) * 64);
    IV = malloc(sizeof(char) * 64);
    cipher = malloc(sizeof(char) * strlen((char *)buffer) - 64 - 64 - 16);
    result = malloc(sizeof(char) * strlen((char *)buffer) - 64 - 64 - 16);

    dump_buf("\n  . get client data ... ok", buffer, strlen((char *)buffer));

    parse_client_request(buffer, IV, ADD, cipher, tag);
    dump_buf("\n  . IV:--------", IV, 64);
    dump_buf("\n  . ADD:--------", ADD, 64);
    dump_buf("\n  . tag:--------", tag, 16);
    dump_buf("\n  . cipher:--------", cipher,
             strlen((char *)buffer) - 64 - 64 - 16);

    // decrypt the ciphet to get address
    char *SERVER_NAME;
    decrypt_aes_gcm(key, cipher, IV, ADD, tag, result);
    printf("\n\n\n%s\n\n\n", result);

    return 0;

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
    printf("\n  . Connecting to tcp/%s/%4d...", SERVER_NAME, SERVER_PORT);
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
    request_server_addr.sin_port = htons(SERVER_PORT);

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
      len = sizeof(server_use_buf) - 1;
      memset(server_use_buf, 0, sizeof(server_use_buf));
      ret = read(request_server_fd, server_use_buf, len);

      if (ret <= 0) {
        printf("failed\n  ! ssl_read returned %d\n\n", ret);
        break;
      }

      len = ret;
      total_response_len += len;
      printf(" %d bytes read\n\n%s", len, server_use_buf);
      // send back to client
      write(clnt_sock, server_use_buf, len);
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
                         unsigned char *tag) {

  strncpy((char *)IV, (char *)buffer, 64);
  strncpy((char *)ADD, (char *)buffer + 64, 64);
  strncpy((char *)tag, (char *)buffer + 64 + 64, 16);
  strncpy((char *)cipher, (char *)buffer + 64 + 64 + 16,
          strlen((char *)buffer) - 64 - 64 - 16);

  return 0;
}

int decrypt_aes_gcm(char *key, unsigned char *input, unsigned char *iv,
                    unsigned char *add, unsigned char *tag,
                    unsigned char *result) {
  printf("%lu", strlen((char *)input));
  unsigned char *target_address = malloc(sizeof(char) * strlen((char *)input));
  size_t len = strlen((char *)input);

  printf("%lu", len);

  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(&ctx);
  info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
  mbedtls_cipher_setup(&ctx, info);
  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(&ctx),
                 mbedtls_cipher_get_block_size(&ctx));

  mbedtls_cipher_setkey(&ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_DECRYPT);

  int ret = mbedtls_cipher_auth_decrypt(
      &ctx, (const unsigned char *)iv, strlen((char *)iv),
      (const unsigned char *)add, strlen((char *)add), input, len,
      target_address, &len, tag, 16);

  printf("%02x", ret);
  memcpy(result, target_address, len);

  return ret;
}

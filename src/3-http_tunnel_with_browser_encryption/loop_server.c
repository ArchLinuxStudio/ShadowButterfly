#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tools.c"

char remote_host[128];
int remote_port;

int extract_host(const char *header) {

  char *_p =
      strstr(header, "CONNECT"); /* parse host and port in CONNECT tunnel*/
  if (_p) {
    char *_p1 = strchr(_p, ' ');

    char *_p2 = strchr(_p1 + 1, ':');
    char *_p3 = strchr(_p1 + 1, ' ');

    if (_p2) {
      char s_port[10];
      bzero(s_port, 10);

      strncpy(remote_host, _p1 + 1, (int)(_p2 - _p1) - 1);
      strncpy(s_port, _p2 + 1, (int)(_p3 - _p2) - 1);
      remote_port = atoi(s_port);

    } else {
      strncpy(remote_host, _p1 + 1, (int)(_p3 - _p1) - 1);
      remote_port = 80;
    }

    return 0;
  }

  // if not CONNECT tunnel, it is HTTP request, parse from normal Host
  char *p = strstr(header, "Host:");
  if (!p) {
    printf("\n---BAD_HTTP_PROTOCOL---\n");
    return BAD_HTTP_PROTOCOL;
  }
  char *p1 = strchr(p, '\n');
  if (!p1) {
    printf("\n---BAD_HTTP_PROTOCOL---\n");
    return BAD_HTTP_PROTOCOL;
  }

  char *p2 =
      strchr(p + 5, ':'); /* 5 is the length of 'Host:', here wants to
                             get port split point next (if port exists) */
  if (p2 && p2 < p1) {
    int p_len = (int)(p1 - p2 - 1);
    char s_port[p_len];
    strncpy(s_port, p2 + 1, p_len);
    s_port[p_len] = '\0';
    remote_port = atoi(s_port);

    int h_len = (int)(p2 - p - 5 - 1);
    strncpy(remote_host, p + 5 + 1, h_len); // Host:
    // assert h_len < 128;
    remote_host[h_len] = '\0';
  } else {
    int h_len = (int)(p1 - p - 5 - 1 - 1);
    strncpy(remote_host, p + 5 + 1, h_len);
    // assert h_len < 128;
    remote_host[h_len] = '\0';
    remote_port = 80;
  }
  return 0;
}

int main() {
  // init socket
  int local_serv_sock = init_server(REMOTE_SERVER_ADDRESS, REMOTE_SERVER_PORT);

  // accept proxy client request
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size = sizeof(clnt_addr);

  // buffer to accept client message
  unsigned char buffer[BUF_SIZ] = {0};

  // init mbedtls
  mbedtls_cipher_context_t *ctx;
  ctx = malloc(sizeof(mbedtls_cipher_context_t));
  memset(ctx, 0, sizeof(mbedtls_cipher_context_t));
  init_cipher_context(ctx, MBEDTLS_CIPHER_AES_256_GCM);
  mbedtls_printf("\n  ------ init cipher content......ok.\n");

  // main loop
  while (1) {
    int ret = 0;

    // accept
    int clnt_sock =
        accept(local_serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

    // use child process to deal with single proxy client request
    if (fork() == 0) {

      close(local_serv_sock);

      // 1: get and parse IV and ADD
      unsigned char IV[IV_LENGTH] = {0};
      unsigned char ADD[ADD_LENGTH] = {0};
      int IV_ADD_READ = 0;
      while (1) {
        IV_ADD_READ = receive_data(clnt_sock, buffer + IV_ADD_READ,
                                   IV_LENGTH + ADD_LENGTH - IV_ADD_READ);
        if (IV_ADD_READ == IV_LENGTH + ADD_LENGTH)
          break;

        if (IV_ADD_READ < IV_LENGTH + ADD_LENGTH) {
          IV_ADD_READ += IV_ADD_READ;
          continue;
        }
      }
      memcpy(IV, buffer, IV_LENGTH);
      memcpy(ADD, buffer + ADD_LENGTH, ADD_LENGTH);
      memset(buffer, 0, BUF_SIZ);

      // 2: parse header buffer to get host
      int k = receive_data(clnt_sock, buffer, BUF_SIZ);

      //解密header
      unsigned char decrypt_result[BUF_SIZ] = {0};
      //首先解析buffer的前5字节，获取密文长度
      char length_buffer[CIPHER_LENGTH] = {
          0}; //存储单次加解密过程的、密文长度的5字节长度buf
      memcpy(length_buffer, buffer, CIPHER_LENGTH);
      //提取单次解密数据的buf
      unsigned char single_decrypt_buf[BUF_SIZ] = {0};
      memcpy(single_decrypt_buf, buffer + CIPHER_LENGTH, atoi(length_buffer));

      int decrypt_result_length = 0;

      decrypt_aes_gcm(KEY, single_decrypt_buf, atoi(length_buffer), IV, ADD,
                      decrypt_result, &decrypt_result_length, ctx);

      printf("get header: %s\n", decrypt_result);
      if (extract_host((const char *)decrypt_result)) {
        continue;
      }

      // 3: connect with target server
      struct hostent *target_server;

      if ((target_server = gethostbyname(remote_host)) == NULL) {
        errno = EFAULT;
        return -1;
      }

      in_addr_t target_server_address;
      memcpy(&target_server_address, target_server->h_addr,
             target_server->h_length);
      int target_serv_sock = create_connect(target_server_address, remote_port);

      // 4: fork
      if (fork() == 0) {
        printf("forward proxy client data to target server\n");
        forward_data_from_server_to_browser_decrypt(clnt_sock, target_serv_sock,
                                                    IV, ADD, ctx);
        exit(0);
      }

      if (fork() == 0) {
        printf("forward proxy target server data to proxy client\n");
        forward_data_from_browser_to_server_encrypt(target_serv_sock, clnt_sock,
                                                    IV, ADD, ctx);
        exit(0);
      }

      close(target_serv_sock);
      close(clnt_sock);

      exit(0);
    }
  }

  close(local_serv_sock);

  return 0;
}
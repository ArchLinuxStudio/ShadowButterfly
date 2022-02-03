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

/* response CONNECT request  */
int send_tunnel_ok(int client_sock) {
  char *resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
  int len = strlen(resp);
  char buffer[len + 1];
  strcpy(buffer, resp);
  if (send(client_sock, buffer, len, 0) < 0) {
    perror("Send http tunnel response  failed\n");
    return -1;
  }
  return 0;
}

int main() {
  // init socket
  int local_serv_sock = init_server(LOCAL_SERVER_ADDRESS, LOCAL_SERVER_PORT);

  // accept browser request
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size = sizeof(clnt_addr);

  // init mbedtls
  mbedtls_cipher_context_t *ctx;
  ctx = malloc(sizeof(mbedtls_cipher_context_t));
  memset(ctx, 0, sizeof(mbedtls_cipher_context_t));
  init_cipher_context(ctx, MBEDTLS_CIPHER_AES_256_GCM);
  mbedtls_printf("\n  ------ init cipher content......ok.\n");

  // main loop
  while (1) {
    // accept
    int clnt_sock =
        accept(local_serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

    // make child process to deal with single browser request
    if (fork() == 0) {
      close(local_serv_sock);
      int remote_serv_sock =
          create_connect(inet_addr(REMOTE_SERVER_ADDRESS), REMOTE_SERVER_PORT);

      // init IV
      unsigned char IV[IV_LENGTH] = {0};
      ctr_drbg_random(IV_LENGTH, IV);
      // init ADD
      unsigned char ADD[ADD_LENGTH] = {0};
      ctr_drbg_random(ADD_LENGTH, ADD);
      mbedtls_printf("\n  ------ init IV&ADD......ok.\n");

      // use child process to forward browser data to remote proxy server
      // because function 'forward_data' is a loop, and stop time is
      // indeterminate, so can't do it in current father process
      if (fork() == 0) {

        // 先发送本次通信的加密参数 服务器接收时对应解密获取共享的参数
        // 固定IV_LENGTH + ADD_LENGTH字节
        unsigned char param_send[BUF_SIZ] = {0};
        memcpy(param_send, IV, IV_LENGTH);
        memcpy(param_send + IV_LENGTH, ADD, ADD_LENGTH);
        send_data(remote_serv_sock, param_send, IV_LENGTH + ADD_LENGTH);

        // 发送接下来的加密数据
        printf("forward browser data to remote proxy server\n");
        forward_data_from_browser_to_server_encrypt(clnt_sock, remote_serv_sock,
                                                    IV, ADD, ctx);
        exit(0);
      }

      // use child process to forward remote proxy server data to browser
      if (fork() == 0) {
        printf("forward remote proxy server data to browser\n");
        // before forward remote proxy server data to browser, need to return
        // 200 OK to browser. this is the specification.
        send_tunnel_ok(clnt_sock);

        //接收服务器传回的数据，解密后再发送给浏览器
        forward_data_from_server_to_browser_decrypt(remote_serv_sock, clnt_sock,
                                                    IV, ADD, ctx);
        exit(0);
      }

      close(remote_serv_sock);
      close(clnt_sock);
      exit(0);
    }
  }

  close(local_serv_sock);

  return 0;
}
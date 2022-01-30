#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tools.h"

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

      // use child process to forward browser data to remote proxy server
      // because function 'forward_data' is a loop, and stop time is
      // indeterminate, so can't do it in current father process
      if (fork() == 0) {
        printf("forward browser data to remote proxy server\n");
        forward_data(clnt_sock, remote_serv_sock);
        exit(0);
      }

      // use child process to forward remote proxy server data to browser
      if (fork() == 0) {
        printf("forward remote proxy server data to browser\n");
        // before forward remote proxy server data to browser, need to return
        // 200 OK to browser. this is the specification.
        send_tunnel_ok(clnt_sock);
        forward_data(remote_serv_sock, clnt_sock);
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
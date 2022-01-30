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
  char buffer[BUFSIZ] = {0};

  // main loop
  while (1) {
    int ret = 0;

    // accept
    int clnt_sock =
        accept(local_serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

    // use child process to deal with single proxy client request
    if (fork() == 0) {

      close(local_serv_sock);

      // parse header buffer to get host
      int k = receive_data(clnt_sock, buffer, BUFSIZ);
      printf("get header:%s\n", buffer);
      extract_host(buffer);

      // connect with target server
      struct hostent *target_server;

      if ((target_server = gethostbyname(remote_host)) == NULL) {
        errno = EFAULT;
        return -1;
      }

      in_addr_t target_server_address;
      memcpy(&target_server_address, target_server->h_addr,
             target_server->h_length);
      int target_serv_sock = create_connect(target_server_address, remote_port);

      if (fork() == 0) {
        printf("forward proxy client data to target server\n");
        forward_data(clnt_sock, target_serv_sock);
        exit(0);
      }

      if (fork() == 0) {
        printf("forward proxy target server data to proxy client\n");
        forward_data(target_serv_sock, clnt_sock);
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
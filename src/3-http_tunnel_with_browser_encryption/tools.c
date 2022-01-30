#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOCAL_SERVER_ADDRESS "127.0.0.1"
#define LOCAL_SERVER_PORT 6789

#define REMOTE_SERVER_ADDRESS "127.0.0.1"
#define REMOTE_SERVER_PORT 5678

#define BAD_HTTP_PROTOCOL -9

void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  printf("%s", info);
  for (int i = 0; i < len; i++) {
    printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
           i == len - 1 ? "\n" : "");
  }
}

int send_data(int socket, char *buffer, int len) {
  return send(socket, buffer, len, 0);
}

int receive_data(int socket, char *buffer, int len) {
  return recv(socket, buffer, len, 0);
}

void forward_data(int source_sock, int destination_sock) {
  char buffer[BUFSIZ];
  int n;

  while ((n = receive_data(source_sock, buffer, BUFSIZ)) > 0) {
    send_data(destination_sock, buffer, n);
  }

  shutdown(destination_sock, SHUT_RDWR);

  shutdown(source_sock, SHUT_RDWR);
}

int init_server(char *server_address, int server_port) {
  // init socket
  int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind & setsockopt
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(server_address);
  serv_addr.sin_port = htons(server_port);
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
  return serv_sock;
}

int create_connect(in_addr_t server_address, int server_port) {
  struct sockaddr_in remote_serv_addr;
  memset(&remote_serv_addr, 0, sizeof(remote_serv_addr));
  remote_serv_addr.sin_family = AF_INET;
  remote_serv_addr.sin_addr.s_addr = server_address;
  remote_serv_addr.sin_port = htons(server_port);

  int remote_serv_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(remote_serv_sock, (struct sockaddr *)&remote_serv_addr,
              sizeof(remote_serv_addr)) == -1)
    return -1;
  return remote_serv_sock;
}
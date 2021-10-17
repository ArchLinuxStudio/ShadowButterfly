#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define SERVER_PORT 80

int main() {
  // init socket
  int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // bind & setsockopt
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
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
  char buffer[BUFSIZ] = {0};

  // main loop
  while (1) {
    // accept
    int clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    read(clnt_sock, buffer,
         sizeof(buffer) - 1); // read client data, here is website domain
    char *SERVER_NAME = buffer;

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

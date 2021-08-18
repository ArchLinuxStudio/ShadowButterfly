#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
  // initiate struct sockaddr_in of the server (specific IP and port)
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET; // ipv4
  serv_addr.sin_addr.s_addr =
      inet_addr("127.0.0.1");       // change to your server ip
  serv_addr.sin_port = htons(6789); // change to your server port

  char buf_send[BUFSIZ] = {0}; // send request web page buffer
  char buf_recv[BUFSIZ] = {0}; // receive response buffer

  while (1) {
    // create socket
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1)
      return -1;
    // get the string entered by the user and send it to the server
    printf("Input a string: ");
    fgets(buf_send, BUFSIZ, stdin);
    // trim \n
    buf_send[strlen(buf_send) - 1] = 0;
    send(serv_sock, buf_send, strlen(buf_send), 0);

    do {
      memset(buf_recv, 0, sizeof(buf_recv));
      // receive the data returned by the server
      int ret = recv(serv_sock, buf_recv, sizeof(buf_recv) - 1, 0);
      if (ret <= 0) {
        printf("failed\n  ! read finished %d\n\n", ret);
        break;
      }
      // only print in this example
      printf("\n\n%lu bytes readed\n\n", strlen(buf_recv));
      printf("\n\nMessage form server: %s\n\n", buf_recv);

    } while (1);

    memset(buf_send, 0, BUFSIZ); // reset buf
    memset(buf_recv, 0, BUFSIZ);
    close(serv_sock);
  }

  return 0;
}
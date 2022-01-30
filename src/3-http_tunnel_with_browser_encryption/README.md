# ShadowButterfly

Basic HTTP tunnel sample without encryption for browser and other client program.

## usage

```bash
gcc loop_client.c
gcc loop_server.c -o b.out
```

## process

client:

1. start local server
2. accept browser request
3. fork a child process to deal with the request
4. create_connect with remote server
5. send 200 OK to browser
6. deal with the request, fork other two child process to forward data between client and server

server:

1. start local server
2. accept client request
3. fork a child process to deal with the request
4. read and parse header first
5. create_connect with target server
6. deal with the request, fork other two child process to forward data between client and server

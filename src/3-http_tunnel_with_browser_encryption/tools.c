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

#define LOCAL_SERVER_ADDRESS "127.0.0.1"
#define LOCAL_SERVER_PORT 6789

#define REMOTE_SERVER_ADDRESS "127.0.0.1"
#define REMOTE_SERVER_PORT 5678

#define BAD_HTTP_PROTOCOL -9

#define IV_LENGTH 64
#define ADD_LENGTH 64
#define TAG_LENGTH 16
#define CIPHER_LENGTH 5

#define KEY "qdEDMtTtJviT/o3V2fa2hKm0+00lT9/1"

#define BUF_SIZ 10000

void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  printf("%s", info);
  for (int i = 0; i < len; i++) {
    printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
           i == len - 1 ? "\n" : "");
  }
}

int encrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add,
                    unsigned char *ret_cipher, int *length,
                    mbedtls_cipher_context_t *ctx) {
  int ret;
  size_t len;
  mbedtls_cipher_setkey(ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_ENCRYPT);

  ret = mbedtls_cipher_auth_encrypt_ext(
      ctx, iv, IV_LENGTH, add, ADD_LENGTH, (const unsigned char *)input,
      input_length, ret_cipher, BUF_SIZ, &len, TAG_LENGTH);
  if (ret != 0) {
    printf("\nencrypt failed! -0x%04X\n", -ret);
  }
  *length = len;
  return ret;
}

int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add,
                    unsigned char *result, int *length,
                    mbedtls_cipher_context_t *ctx) {

  size_t result_len = 0;

  mbedtls_cipher_setkey(ctx, (const unsigned char *)key, strlen(key) * 8,
                        MBEDTLS_DECRYPT);

  int ret = mbedtls_cipher_auth_decrypt_ext(ctx, iv, IV_LENGTH, add, ADD_LENGTH,
                                            input, input_length, result,
                                            BUF_SIZ, &result_len, TAG_LENGTH);

  *length = result_len;
  if (ret != 0) {
    printf("\n decrypt failed! -0x%04X\n", -ret);
    exit(0);
  } else {
    printf("decrypt ok.\n");
  }

  return ret;
}

int send_data(int socket, unsigned char *buffer, int len) {
  return send(socket, buffer, len, 0);
}

int receive_data(int socket, unsigned char *buffer, int len) {
  return recv(socket, buffer, len, 0);
}

// 发送时是从浏览器或目标服务器读取，然后加密
// 所以可以放心大胆的读完就加密、发送。
void forward_data_from_browser_to_server_encrypt(
    int source_sock, int destination_sock, unsigned char *IV,
    unsigned char *ADD, mbedtls_cipher_context_t *ctx) {

  unsigned char buffer[BUF_SIZ];
  int n;

  //减去这几个参数防止读多了数组越界
  // TODO? 这里不能读太多 如果读大了 之后会数组越界 需要进一步确定
  while ((n = receive_data(source_sock, buffer,
                           BUF_SIZ - TAG_LENGTH - CIPHER_LENGTH - 1)) > 0) {

    // while ((n = receive_data(source_sock, buffer, BUF_SIZ / 2)) > 0) {
    printf("encrypt read n:%d\n", n);
    //加密buffer 需要记录并发送密文长度
    unsigned char cipher_buf[BUF_SIZ] = {0};
    int cipher_buf_length = 0;
    encrypt_aes_gcm(KEY, buffer, n, IV, ADD, cipher_buf, &cipher_buf_length,
                    ctx);

    // cipher length + cipher
    unsigned char send_cipher[BUF_SIZ] = {0};
    char length_buffer[CIPHER_LENGTH] = {0};
    sprintf(length_buffer, "%d", cipher_buf_length);
    memcpy(send_cipher, length_buffer, CIPHER_LENGTH);
    memcpy(send_cipher + CIPHER_LENGTH, cipher_buf, cipher_buf_length);

    send_data(destination_sock, send_cipher, CIPHER_LENGTH + cipher_buf_length);
  }

  shutdown(destination_sock, SHUT_RDWR);

  shutdown(source_sock, SHUT_RDWR);
}

//接收数据时比较麻烦 因为不一定能够按照加密长度的大小收到全部数据。
//可能一次收的数据不足一个加密块
//可能一次收的数据正好一个加密块
//可能一次收的数据大于一个加密块
//可能一次收的数据大一一个以上加密块的长度
//由于接受数据时，不一定能接收到发送方指定的大小的加密块大小，所以要分情况讨论
void forward_data_from_server_to_browser_decrypt(
    int source_sock, int destination_sock, unsigned char *IV,
    unsigned char *ADD, mbedtls_cipher_context_t *ctx) {
  unsigned char buffer[BUF_SIZ];
  int n;

  int single_decrypt_length; //单次加解密过程中、前五个字节的、密文长度的实际大小(此长度包含了TAG_LENGTH)
  char length_buffer[CIPHER_LENGTH] = {
      0}; //存储单次加解密过程的、密文长度的5字节长度的buffer
  int tmp_read_length; //循环进行过程中，目前已经读取了多少字节的数据。不包括单次加解密起始的CIPHER_LENGTH字节
  unsigned char tmp_cipher_buf[BUF_SIZ] = {
      0}; //循环进行过程中,暂存已经读取到的buffer。不包括单次加解密起始的CIPHER_LENGTH字节
  int decrypt_round_start =
      1; //记录当前的解密状态是否为单次解密的开始，初始状态是单次解密的开始

  //这里减去tmp_read_length。如果不减去，在接续时tmp_cipher_buf +
  // tmp_read_length 如果超出了数组长度，则会溢出。
  while ((n = receive_data(source_sock, buffer,
                           BUF_SIZ - tmp_read_length - 1)) > 0) {
    //如果当前是单次解密读取的开始，则需要记录如下数据
    if (decrypt_round_start) {
      //首先解析buffer的前5字节，获取密文长度
      memset(length_buffer, 0, CIPHER_LENGTH);

      //兼容上次未读满CIPHER_LENGTH的情况
      memcpy(length_buffer, tmp_cipher_buf, tmp_read_length);
      //再存入新的数据
      memcpy(length_buffer + tmp_read_length, buffer,
             CIPHER_LENGTH - tmp_read_length);
      single_decrypt_length = atoi(length_buffer);
      //暂存目前读取到的密文
      memset(tmp_cipher_buf, 0, BUF_SIZ);
      //兼容上次未读满CIPHER_LENGTH的情况
      memcpy(tmp_cipher_buf, buffer - tmp_read_length + CIPHER_LENGTH,
             n + tmp_read_length - CIPHER_LENGTH);
      //记录目前已读取多少字节密文长度(不含CIPHER_LENGTH)
      tmp_read_length = n + tmp_read_length - CIPHER_LENGTH;
    } else { //如果不是单次解密读取的开始，需要记录的数据方式与上面不同
      //暂存目前读取到的密文
      memcpy(tmp_cipher_buf + tmp_read_length, buffer, n);
      //记录目前已读取多少字节
      tmp_read_length += n;
    }

    //目前读取的数据长度不足，不能解密，需要暂存目前已有数据并继续读
    if (tmp_read_length < single_decrypt_length) {
      decrypt_round_start = 0;
      continue;
    }

    //目前读取的数据长度超出单次解密长度，可以进行解密和转发
    //长度超出单次解密，还需暂存解密后剩余的数据和长度，用于下次解密和转发
    //可能超出多次单个加解密次数 所以用while

    while (tmp_read_length > single_decrypt_length) {
      printf("bigger\n");
      printf("single_decrypt_length:%d\n", single_decrypt_length);
      printf("tmp_read_length:%d\n", tmp_read_length);

      unsigned char decrypt_result[BUF_SIZ] = {0};
      memset(decrypt_result, 0, BUF_SIZ);
      int decrypt_result_length = 0;

      //提取单次解密数据的buf
      unsigned char single_decrypt_buf[BUF_SIZ] = {0};
      memset(single_decrypt_buf, 0, BUF_SIZ);
      memcpy(single_decrypt_buf, tmp_cipher_buf, single_decrypt_length);

      decrypt_aes_gcm(KEY, single_decrypt_buf, single_decrypt_length, IV, ADD,
                      decrypt_result, &decrypt_result_length, ctx);

      send_data(destination_sock, decrypt_result, decrypt_result_length);

      //////////////////

      // 更新暂存buf tmp_cipher_buf的值，并更新相关变量的状态值
      tmp_read_length -= single_decrypt_length;

      unsigned char tmp[BUF_SIZ] = {0};
      memcpy(tmp, tmp_cipher_buf + single_decrypt_length, tmp_read_length);
      memset(tmp_cipher_buf, 0, BUF_SIZ);
      memcpy(tmp_cipher_buf, tmp, tmp_read_length);

      printf("\n\nrest length %d\n\n", tmp_read_length);
      dump_buf("rest length REX", tmp_cipher_buf, CIPHER_LENGTH);

      // 解析buffer的前CIPHER_LENGTH字节，获取新的一次加解密中密文长度
      //  可能剩余的数据 不够CIPHER_LENGTH字节来解析下次加密时的加密块长度
      if (tmp_read_length < CIPHER_LENGTH) {
        //不满CIPHER_LENGTH 还是需要重新读，状态为单次解密开始
        single_decrypt_length = 0;
        decrypt_round_start = 1;
        break;
      }

      memset(length_buffer, 0, CIPHER_LENGTH);
      memcpy(length_buffer, tmp_cipher_buf, CIPHER_LENGTH);
      single_decrypt_length = atoi(length_buffer);
      //若剩下的字节不足够解析下一次，continue
      if (tmp_read_length < single_decrypt_length + CIPHER_LENGTH) {
        printf("\ntoo small! need read again\n");

        //再次更新tmp_cipher_buf  去除CIPHER_LENGTH部分
        memset(tmp, 0, BUF_SIZ);
        memcpy(tmp, tmp_cipher_buf + CIPHER_LENGTH,
               tmp_read_length - CIPHER_LENGTH);
        memset(tmp_cipher_buf, 0, BUF_SIZ);
        memcpy(tmp_cipher_buf, tmp, tmp_read_length - CIPHER_LENGTH);

        tmp_read_length -= CIPHER_LENGTH;
        decrypt_round_start = 0;
        break;
      }

      //若剩下的字节足够解析下一次，则在当前wile继续处理

      //再次更新tmp_cipher_buf  去除CIPHER_LENGTH部分
      memset(tmp, 0, BUF_SIZ);
      memcpy(tmp, tmp_cipher_buf + CIPHER_LENGTH,
             tmp_read_length - CIPHER_LENGTH);
      memset(tmp_cipher_buf, 0, BUF_SIZ);
      memcpy(tmp_cipher_buf, tmp, tmp_read_length - CIPHER_LENGTH);

      tmp_read_length -= CIPHER_LENGTH;

      decrypt_round_start = 1;
    }

    // 目前读取了的长度刚好等于单次解密的长度，这时进行解密buffer，转发，清空buffer和状态，继续接收
    if (tmp_read_length == single_decrypt_length) {
      printf("equal\n");
      printf("single_decrypt_length:%d\n", single_decrypt_length);
      printf("tmp_read_length:%d\n", tmp_read_length);
      unsigned char decrypt_result[BUF_SIZ] = {0};
      int decrypt_result_length = 0;

      decrypt_aes_gcm(KEY, tmp_cipher_buf, single_decrypt_length, IV, ADD,
                      decrypt_result, &decrypt_result_length, ctx);

      send_data(destination_sock, decrypt_result, decrypt_result_length);

      //解密、转发、清空buffer、继续循环
      decrypt_round_start = 1;
      single_decrypt_length = 0;
      tmp_read_length = 0;
      memset(tmp_cipher_buf, 0, BUF_SIZ);
    }
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

int init_cipher_context(mbedtls_cipher_context_t *ctx,
                        mbedtls_cipher_type_t type) {
  int ret;
  const mbedtls_cipher_info_t *info;

  mbedtls_cipher_init(ctx);
  info = mbedtls_cipher_info_from_type(type);
  ret = mbedtls_cipher_setup(ctx, info);
  if (ret != 0) {
    printf("\n mbedtls_cipher_setup failed! -0x%04X\n", -ret);
  }
  mbedtls_printf("cipher info setup, name: %s, block size: %d\n",
                 mbedtls_cipher_get_name(ctx),
                 mbedtls_cipher_get_block_size(ctx));
  return ret;
}

int ctr_drbg_random(int length, unsigned char *random_num) {
  int ret = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  char pers[] = "SHADOWBUTTERFLY_CTR_DRBG";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    fprintf(stderr, "mbedtls_ctr_drbg_seed error! return: -0x%04X \n", -ret);
    return ret;
  }
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, random_num, length);

  if (ret != 0) {
    fprintf(stderr, "mbedtls_ctr_drbg_random error! return: -0x%04X \n", -ret);
    return ret;
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}

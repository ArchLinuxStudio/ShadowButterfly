#include "tools.c"

/**
 * \brief               This function sets a random number of a specified
 *                      length.
 *
 * \param length        The length of the random number required, in bytes.
 * \param random_num    random number to use. In \p length bytes.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      #MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
int ctr_drbg_random(int length, unsigned char *random_num);

/**
 * \brief               Receive data and related parameters for AEAD encryption.
 *                      mbedtls_cipher_context_t must be initialized.
 *
 * \param key           Symmetric encryption key.
 * \param input         Data to be encrypted.
 * \param input_length
 * \param iv            IV or Nonce to be used in AEAD.
 * \param add           Additional Data to be used in AEAD.
 * \param ret_cipher    Generated ciphertext.
 * \param length        \p ret_cipher length.
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key associated with an AEAD algorithm.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int encrypt_aes_gcm(char *key, char *input, int input_length, unsigned char *iv,
                    unsigned char *add, unsigned char *ret_cipher, int *length,
                    mbedtls_cipher_context_t *ctx);

/**
 * \brief               Receive cipher and related parameters for AEAD
 *                      decryption. mbedtls_cipher_context_t must be
 *                      initialized.
 *
 * \param key           Symmetric encryption key.
 * \param input         Data to be decrypted.
 * \param input_length  \p input cipher length.
 * \param iv            IV or Nonce to be used in AEAD.
 * \param add           Additional Data to be used in AEAD.
 * \param result        Generated plaintext.
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key associated with an AEAD algorithm.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_AUTH_FAILED if data is not
 * authentic. \return              A cipher-specific error code on failure.
 */
int decrypt_aes_gcm(char *key, unsigned char *input, int input_length,
                    unsigned char *iv, unsigned char *add,
                    unsigned char *result, mbedtls_cipher_context_t *ctx);

/**
 * \brief               This function outputs the data in a format that is
 *                      convenient for humans to read, and can output a line of
 *                      prompt information at the same time.
 *
 * \param info          The length of the random number required, in bytes.
 * \param buf           input buffer.
 * \param len           \p buf length.
 * \return              NONE
 */
void dump_buf(char *info, uint8_t *buf, uint32_t len);

/**
 * \brief               This function init and setup cipher context.
 *
 * \param ctx           mbedtls cipher context to be init and setup.
 * \param type          AEAD algorithm.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 */
int init_cipher_context(mbedtls_cipher_context_t *ctx,
                        mbedtls_cipher_type_t type);
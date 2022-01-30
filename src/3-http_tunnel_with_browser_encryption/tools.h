#include "tools.c"

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

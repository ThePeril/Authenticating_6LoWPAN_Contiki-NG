#ifndef __TC_HMAC_H__
#define __TC_HMAC_H__

#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tc_hmac_state_struct {
	/* the internal state required by h */
	struct tc_sha256_state_struct hash_state;
	/* HMAC key schedule */
	uint8_t key[2*TC_SHA256_BLOCK_SIZE];
};
typedef struct tc_hmac_state_struct *TCHmacState_t;

/**
 *  @brief HMAC set key procedure
 *  Configures ctx to use key
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if
 *                ctx == NULL or
 *                key == NULL or
 *                key_size == 0
 * @param ctx IN/OUT -- the struct tc_hmac_state_struct to initial
 * @param key IN -- the HMAC key to configure
 * @param key_size IN -- the HMAC key size
 */
int tc_hmac_set_key(TCHmacState_t ctx, const uint8_t *key,
		    unsigned int key_size);

/**
 * @brief HMAC init procedure
 * Initializes ctx to begin the next HMAC operation
 * @return returns TC_CRYPTO_SUCCESS (1)
 *         returns TC_CRYPTO_FAIL (0) if: ctx == NULL or key == NULL
 * @param ctx IN/OUT -- struct tc_hmac_state_struct buffer to init
 */
int tc_hmac_init(TCHmacState_t ctx);

/**
 *  @brief HMAC update procedure
 *  Mixes data_length bytes addressed by data into state
 *  @return returns TC_CRYPTO_SUCCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if: ctx == NULL or key == NULL
 *  @note Assumes state has been initialized by tc_hmac_init
 *  @param ctx IN/OUT -- state of HMAC computation so far
 *  @param data IN -- data to incorporate into state
 *  @param data_length IN -- size of data in bytes
 */
int tc_hmac_update(TCHmacState_t ctx, const void *data,
		   unsigned int data_length);

/**
 *  @brief HMAC final procedure
 *  Writes the HMAC tag into the tag buffer
 *  @return returns TC_CRYPTO_SUCCESS (1)
 *          returns TC_CRYPTO_FAIL (0) if:
 *                tag == NULL or
 *                ctx == NULL or
 *                key == NULL or
 *                taglen != TC_SHA256_DIGEST_SIZE
 *  @note ctx is erased before exiting. This should never be changed/removed.
 *  @note Assumes the tag bufer is at least sizeof(hmac_tag_size(state)) bytes
 *  state has been initialized by tc_hmac_init
 *  @param tag IN/OUT -- buffer to receive computed HMAC tag
 *  @param taglen IN -- size of tag in bytes
 *  @param ctx IN/OUT -- the HMAC state for computing tag
 */
int tc_hmac_final(uint8_t *tag, unsigned int taglen, TCHmacState_t ctx);

#ifdef __cplusplus
}
#endif

#endif /*__TC_HMAC_H__*/

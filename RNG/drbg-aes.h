/* drbg-aes.h
 *
 * The CTR-AES-256-based random-number generator from SP800-90A.
 */

/* Copyright (C) 2013 Red Hat
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#ifndef DRBG_AES_H_INCLUDED
#define DRBG_AES_H_INCLUDED

#include <nettle/aes.h>

/* This is nettle's increment macro */
/* Requires that size > 0 */
#define INCREMENT(size, ctr)                    \
  do {                                          \
    unsigned increment_i = (size) - 1;          \
    if (++(ctr)[increment_i] == 0)              \
      while (increment_i > 0                    \
             && ++(ctr)[--increment_i] == 0 )   \
        ;                                       \
  } while (0)

#define DRBG_AES_KEY_SIZE 32
#define DRBG_AES_SEED_SIZE (AES_BLOCK_SIZE+DRBG_AES_KEY_SIZE)

/* This is the CTR-AES-256-based random-number generator from SP800-90A.
 */
struct drbg_aes_ctx {
	unsigned seeded;
	/* The current key */
	struct aes_ctx key;

	uint8_t v[AES_BLOCK_SIZE];

	unsigned prev_block_present;
	uint8_t prev_block[AES_BLOCK_SIZE];
	unsigned reseed_counter;
};

/* This DRBG should be reseeded if reseed_counter exceeds
 * that number. Otherwise drbg_aes_random() will fail.
 */
#define DRBG_AES_RESEED_TIME 65536

/* The entropy provided in these functions should be of
 * size DRBG_AES_SEED_SIZE. Additional data and pers.
 * string may be <= DRBG_AES_SEED_SIZE.
 */
int
drbg_aes_init(struct drbg_aes_ctx *ctx, 
	unsigned entropy_size, const uint8_t *entropy, 
	unsigned pstring_size, const uint8_t* pstring);

int
drbg_aes_reseed(struct drbg_aes_ctx *ctx, 
	unsigned entropy_size, const uint8_t *entropy, 
	unsigned add_size, const uint8_t* add);

#define drbg_aes_random(ctx, l, dst) drbg_aes_generate(ctx, l, dst, 0, NULL)

int
drbg_aes_generate(struct drbg_aes_ctx *ctx, unsigned length,
		uint8_t * dst, unsigned add_size, const uint8_t* add);

int drbg_aes_is_seeded(struct drbg_aes_ctx *ctx);

int drbg_aes_self_test(void);

#endif				/* DRBG_AES_H_INCLUDED */

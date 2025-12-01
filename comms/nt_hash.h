#ifndef NT_NTHASH_H
#define NT_NTHASH_H

#include "../nt_types.h"
#define NT_MD5_DIGEST_SIZE 16

typedef unsigned char md5_byte_t; /* 8-bit byte */
typedef unsigned int md5_word_t; /* 32-bit word */

/* Define the state of the MD5 Algorithm. */
typedef struct md5_state_s
{
	md5_word_t	count[2];	/* message length in bits, lsw first */
	md5_word_t	abcd[4];	/* digest buffer */
	md5_byte_t	buf[64];	/* accumulate block */
} md5_state_t;

#ifdef __cplusplus
extern "C"
{
#endif

/* Initialize the algorithm. */
void nt_md5_init(md5_state_t *pms);

/* Append a string to the message. */
void nt_md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes);

/* Finish the message and return the digest. */
void nt_md5_finish(md5_state_t *pms, md5_byte_t digest[16]);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

/* ------------------ end of included md5.h file ------------------------- */

//#include "nt_common.h"

void	nt_md5buf2str(const md5_byte_t *md5, char *str);

/* SHA BLOCK */
/* Based on SHA256 implementation released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

#define NT_SHA256_DIGEST_SIZE	32

/* Structure to save state of computation between the single steps. */
typedef struct
{
	uint32_t	H[8];
	uint32_t	total[2];
	uint32_t	buflen;
	char		buffer[128];	/* NB: always correctly aligned for uint32_t. */
}
sha256_ctx;

void	nt_sha256_init(sha256_ctx *ctx);
void	nt_sha256_process_bytes(const void *buffer, size_t len, sha256_ctx *ctx);
void	*nt_sha256_finish(sha256_ctx *ctx, void *resbuf);
void	nt_sha256_hash(const char *in, char *out);
void	nt_sha256_hash_len(const char *in, size_t len, char *out);

/* Based on SHA512 implementation released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */
void	nt_sha512_hash(const char *in, char *out);
/* SHA BLOCK END */

#endif /* NT_NTHASH_H */

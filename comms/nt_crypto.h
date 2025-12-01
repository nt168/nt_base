#ifndef NT_NTCRYPTO_H
#define NT_NTCRYPTO_H

#include "nt_types.h"
#include "nt_hash.h"

nt_uint64_t	nt_letoh_uint64(nt_uint64_t data);
nt_uint64_t	nt_htole_uint64(nt_uint64_t data);

nt_uint32_t	nt_letoh_uint32(nt_uint32_t data);
nt_uint32_t	nt_htole_uint32(nt_uint32_t data);

int	nt_hex2bin(const unsigned char *p_hex, unsigned char *buf, int buf_len);
int	nt_bin2hex(const unsigned char *bin, size_t bin_len, char *out, size_t out_len);

#define NT_SESSION_TOKEN_SIZE	(NT_MD5_DIGEST_SIZE * 2)

char	*nt_create_token(nt_uint64_t seed);
char	*nt_gen_uuid4(const char *seed);

typedef enum
{
	NT_HASH_MD5,
	NT_HASH_SHA256
}
nt_crypto_hash_t;

int	nt_hmac(nt_crypto_hash_t hash_type, const char *key, size_t key_len, const char *text, size_t text_len,
		char **out);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
void	nt_normalize_pem(char **key, size_t *key_len);
int	nt_rs256_sign(char *key, size_t key_len, char *data, size_t data_len, unsigned char **output,
		size_t *output_len, char **error);
#endif
int	nt_base64_validate(const char *p_str);
void	nt_base64_encode(const char *p_str, char *p_b64str, int in_size);
void	nt_base64_encode_dyn(const char *p_str, char **p_b64str, int in_size);
void	nt_base64_decode(const char *p_b64str, char *p_str, size_t maxsize, size_t *p_out_size);

#endif /* NT_NTCRYPTO_H */

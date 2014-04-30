#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char key[16];
	unsigned char iv[16];
	unsigned char in[128];
	unsigned char out[128+16];
	int r, len, out_len;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	r = RAND_pseudo_bytes(key, sizeof(key));
	assert(r == 1);
	r = RAND_pseudo_bytes(iv, sizeof(iv));
	assert(r == 1);
	r = RAND_pseudo_bytes(in, sizeof(in));
	assert(r == 1);
	r = RAND_pseudo_bytes(out, sizeof(out));
	assert(r == 1);

	ctx = EVP_CIPHER_CTX_new();
	assert(ctx);

	EVP_CIPHER_CTX_init(ctx);

	len = EVP_CIPHER_key_length(EVP_aes_128_ctr());
	assert(len == sizeof(key));

	len = EVP_CIPHER_iv_length(EVP_aes_128_ctr());
	assert(len == sizeof(iv));

	r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
	assert(r == 1);

	r = EVP_EncryptUpdate(ctx, out, &out_len, in, sizeof(in));
	assert(r == 1);

	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

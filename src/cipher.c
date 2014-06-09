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
	unsigned char ori_msg[128];
	unsigned char enc_msg[128+16];
	unsigned char dec_msg[128];
	int r, len, enc_msg_len, dec_msg_len;
	const EVP_CIPHER* cipher = NULL;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	r = RAND_bytes(key, sizeof(key));
	assert(r == 1);
	r = RAND_bytes(iv, sizeof(iv));
	assert(r == 1);
	r = RAND_pseudo_bytes(ori_msg, sizeof(ori_msg));
	assert(r == 1);
	r = RAND_pseudo_bytes(enc_msg, sizeof(enc_msg));
	assert(r == 1);

	cipher = EVP_aes_128_ctr();

	ctx = EVP_CIPHER_CTX_new();
	assert(ctx);

	EVP_CIPHER_CTX_init(ctx);

	len = EVP_CIPHER_key_length(cipher);
	assert(len == sizeof(key));

	len = EVP_CIPHER_iv_length(cipher);
	assert(len == sizeof(iv));


	r = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
	assert(r == 1);

	r = EVP_EncryptUpdate(ctx, enc_msg, &enc_msg_len, ori_msg, sizeof(ori_msg));
	assert(r == 1);
	assert(enc_msg_len == sizeof(ori_msg));

	r = EVP_EncryptFinal_ex(ctx, enc_msg + enc_msg_len, &len);
	assert(r == 1);
	assert(len == 0);


	r = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
	assert(r == 1);

	r = EVP_DecryptUpdate(ctx, dec_msg, &dec_msg_len, enc_msg, enc_msg_len);
	assert(r == 1);
	assert(dec_msg_len == enc_msg_len);

	r = EVP_DecryptFinal_ex(ctx, dec_msg + dec_msg_len, &len);
	assert(r == 1);
	assert(len == 0);

	assert(memcmp(ori_msg, dec_msg, dec_msg_len) == 0);


	EVP_CIPHER_CTX_free(ctx);

	puts("OK!");
	return 0;
}

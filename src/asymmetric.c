#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static void dump(const void *p, size_t len)
{
	const unsigned char *a = p;
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%02X", a[i]);
	}
	puts("");
}

static void generate_ec_key_pair(EVP_PKEY **key)
{
	EVP_PKEY_CTX *params_ctx = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *params = NULL;
	int r;

	// Generate EC parameters

	params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(params_ctx);

	r = EVP_PKEY_paramgen_init(params_ctx);
	assert(r == 1);

	r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, NID_X9_62_prime256v1);
	assert(r == 1);

	r = EVP_PKEY_paramgen(params_ctx, &params);
	assert(r == 1);

	// Generate key pair

	key_ctx = EVP_PKEY_CTX_new(params, NULL);
	assert(key_ctx);

	r = EVP_PKEY_keygen_init(key_ctx);
	assert(r == 1);

	r = EVP_PKEY_keygen(key_ctx, key);
	assert(r == 1);

	// Free

	if (key_ctx) {
		EVP_PKEY_CTX_free(key_ctx);
	}
	if (params_ctx) {
		EVP_PKEY_CTX_free(params_ctx);
	}
	if (params) {
		EVP_PKEY_free(params);
	}
}

static void generate_rsa_key_pair(EVP_PKEY **key)
{
	EVP_PKEY_CTX *key_ctx = NULL;
	int r;

	// Generate key parameters

	key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	assert(key_ctx);

	r = EVP_PKEY_keygen_init(key_ctx);
	assert(r == 1);

	r = EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 3072);
	assert(r > 0);

	r = EVP_PKEY_keygen(key_ctx, key);
	assert(r == 1);

	// Free

	if (key_ctx) {
		EVP_PKEY_CTX_free(key_ctx);
	}
}

static void encrypt_decrypt(EVP_PKEY *key)
{
	EVP_PKEY_CTX *enc_ctx = NULL;
	unsigned char ori_msg[128];
	unsigned char enc_msg[4096 / 8];
	unsigned char dec_msg[4096 / 8];
	size_t enc_msg_len, dec_msg_len;
	int r;

	r = RAND_pseudo_bytes(ori_msg, sizeof(ori_msg));
	assert(r == 1);

	puts("Plaintext:");
	dump(ori_msg, sizeof(ori_msg));

	// Encrypt

	enc_ctx = EVP_PKEY_CTX_new(key, NULL);
	assert(enc_ctx);

	r = EVP_PKEY_encrypt_init(enc_ctx);
	assert(r == 1);

	if (EVP_PKEY_type(key->type) == EVP_PKEY_RSA) {
		r = EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING);
		assert(r > 0);
	}

	enc_msg_len = sizeof(enc_msg);
	r = EVP_PKEY_encrypt(enc_ctx, enc_msg, &enc_msg_len, ori_msg, sizeof(ori_msg));
	assert(r == 1);

	puts("Ciphertext:");
	dump(enc_msg, enc_msg_len);

	// Decrypt

	r = EVP_PKEY_decrypt_init(enc_ctx);
	assert(r == 1);

	if (EVP_PKEY_type(key->type) == EVP_PKEY_RSA) {
		r = EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING);
		assert(r > 0);
	}

	dec_msg_len = sizeof(dec_msg);
	r = EVP_PKEY_decrypt(enc_ctx, dec_msg, &dec_msg_len, enc_msg, enc_msg_len);
	assert(r == 1);

	puts("Decrypted Plaintext:");
	dump(dec_msg, dec_msg_len);

	// Free

	if (enc_ctx) {
		EVP_PKEY_CTX_free(enc_ctx);
	}
}

int main(void)
{
	EVP_PKEY *key = NULL;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	generate_rsa_key_pair(&key);

	encrypt_decrypt(key);

	EVP_PKEY_free(key);
	key = NULL;

	generate_ec_key_pair(&key);

//	encrypt_decrypt(key);

	puts("OK!");

	if (key) {
		EVP_PKEY_free(key);
	}

	return 0;
}

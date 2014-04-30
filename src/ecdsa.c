#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>


int main(void) {
	EVP_PKEY_CTX *params_ctx = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *params = NULL;
	EVP_PKEY *key = NULL;
	EVP_MD_CTX sign_ctx;
	unsigned char msg[128];
	unsigned char signature[4096 / 8];
	unsigned int signature_len;
	int r;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

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

	r = EVP_PKEY_keygen(key_ctx, &key);
	assert(r == 1);

	// Sign

	r = RAND_pseudo_bytes(msg, sizeof(msg));
	assert(r == 1);

	EVP_MD_CTX_init(&sign_ctx);

	r = EVP_SignInit_ex(&sign_ctx, EVP_sha256(), NULL);
	assert(r == 1);

	r = EVP_SignUpdate(&sign_ctx, msg, sizeof(msg));
	assert(r == 1);

	assert(EVP_PKEY_size(key) <= (int) sizeof(signature));

	r = EVP_SignFinal(&sign_ctx, signature, &signature_len, key);
	assert(r == 1);

	// Verify

	r = EVP_VerifyInit_ex(&sign_ctx, EVP_sha256(), NULL);
	assert(r == 1);

	r = EVP_VerifyUpdate(&sign_ctx, msg, sizeof(msg));
	assert(r == 1);

	r = EVP_VerifyFinal(&sign_ctx, signature, signature_len, key);
	assert(r == 1);

	// Free

	if (key_ctx) {
		EVP_PKEY_CTX_free(key_ctx);
	}
	if (params_ctx) {
		EVP_PKEY_CTX_free(params_ctx);
	}
	if (key) {
		EVP_PKEY_free(key);
	}
	if (params) {
		EVP_PKEY_free(params);
	}

	puts("OK!");

	return 0;
}

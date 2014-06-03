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

static void sign_verify(EVP_PKEY *key)
{
	EVP_PKEY_CTX *sign_key_ctx = NULL;
	EVP_MD_CTX *sign_ctx = NULL;
	unsigned char msg[128];
	unsigned char signature[4096 / 8];
	size_t signature_len;
	int r;

	// Sign

	r = RAND_pseudo_bytes(msg, sizeof(msg));
	assert(r == 1);

	sign_ctx = EVP_MD_CTX_create();
	assert(sign_ctx);

	r = EVP_DigestSignInit(sign_ctx, &sign_key_ctx, EVP_sha256(), NULL, key);
	assert(r == 1);

	if (EVP_PKEY_type(key->type) == EVP_PKEY_RSA) {
		r = EVP_PKEY_CTX_set_rsa_padding(sign_key_ctx, RSA_PKCS1_PSS_PADDING);
		assert(r > 0);

		r = EVP_PKEY_CTX_set_rsa_pss_saltlen(sign_key_ctx, -1);
		assert(r > 0);
	}

	r = EVP_DigestSignUpdate(sign_ctx, msg, sizeof(msg));
	assert(r == 1);

	signature_len = sizeof(signature);
	r = EVP_DigestSignFinal(sign_ctx, signature, &signature_len);
	assert(r == 1);

	puts("Signature:");
	dump(signature, signature_len);

	// Verify

	r = EVP_DigestVerifyInit(sign_ctx, &sign_key_ctx, EVP_sha256(), NULL, key);
	assert(r == 1);

	if (EVP_PKEY_type(key->type) == EVP_PKEY_RSA) {
		r = EVP_PKEY_CTX_set_rsa_padding(sign_key_ctx, RSA_PKCS1_PSS_PADDING);
		assert(r > 0);

		r = EVP_PKEY_CTX_set_rsa_pss_saltlen(sign_key_ctx, -1);
		assert(r > 0);
	}

	r = EVP_DigestVerifyUpdate(sign_ctx, msg, sizeof(msg));
	assert(r == 1);

	r = EVP_DigestVerifyFinal(sign_ctx, signature, signature_len);
	assert(r == 1);

	// Free

	if (sign_ctx) {
		EVP_MD_CTX_destroy(sign_ctx);
	}
}

int main(void)
{
	EVP_PKEY *key = NULL;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	generate_rsa_key_pair(&key);

	sign_verify(key);

	EVP_PKEY_free(key);
	key = NULL;

	generate_ec_key_pair(&key);

	sign_verify(key);

	puts("OK!");

	if (key) {
		EVP_PKEY_free(key);
	}

	return 0;
}

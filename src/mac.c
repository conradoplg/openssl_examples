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

static void generate_hmac_key(EVP_PKEY **key)
{
	unsigned char keybuf[256 / 8];
	int r;

	r = RAND_bytes(keybuf, sizeof(keybuf));
	assert(r == 1);

	*key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keybuf, sizeof(keybuf));
	assert(*key);
}

static void auth_check(EVP_PKEY *key)
{
	EVP_MD_CTX *mac_ctx = NULL;
	unsigned char msg[128];
	unsigned char tag[512 / 8];
	unsigned char computed_tag[512 / 8];
	size_t tag_len, computed_tag_len;
	int r;

	// Authenticate

	r = RAND_pseudo_bytes(msg, sizeof(msg));
	assert(r == 1);

	mac_ctx = EVP_MD_CTX_create();
	assert(mac_ctx);

	r = EVP_DigestSignInit(mac_ctx, NULL, EVP_sha256(), NULL, key);
	assert(r == 1);

	r = EVP_DigestSignUpdate(mac_ctx, msg, sizeof(msg));
	assert(r == 1);

	tag_len = sizeof(tag);
	r = EVP_DigestSignFinal(mac_ctx, tag, &tag_len);
	assert(r == 1);

	puts("MAC:");
	dump(tag, tag_len);

	// Check

	r = EVP_DigestSignInit(mac_ctx, NULL, EVP_sha256(), NULL, key);
	assert(r == 1);

	r = EVP_DigestSignUpdate(mac_ctx, msg, sizeof(msg));
	assert(r == 1);

	computed_tag_len = sizeof(tag);
	r = EVP_DigestSignFinal(mac_ctx, computed_tag, &computed_tag_len);
	assert(r == 1);

	assert(tag_len == computed_tag_len);
	assert(CRYPTO_memcmp(tag, computed_tag, tag_len) == 0);

	// Free

	if (mac_ctx) {
		EVP_MD_CTX_destroy(mac_ctx);
	}
}

int main(void)
{
	EVP_PKEY *key = NULL;

	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	generate_hmac_key(&key);

	auth_check(key);

	puts("OK!");

	if (key) {
		EVP_PKEY_free(key);
	}

	return 0;
}

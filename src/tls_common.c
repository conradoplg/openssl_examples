#include "tls_common.h"

#include <assert.h>
#include <stdlib.h>
#include <openssl/err.h>


void print_ciphers(SSL *ssl)
{
	int pri = 0;
	const char *name;
	while ((name = SSL_get_cipher_list(ssl, pri++)) != NULL) {
		printf("%s:", name);
	}
	puts("");
}

void ssl_setup(SSL_CTX* ctx, char *ca_file, char* cert_file, char* key_file)
{
	if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
		ERR_print_errors_fp(stderr);
	}
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	/* verify private key */
	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}

	//SSL_VERIFY_PEER
	SSL_CTX_set_verify(ctx, 0, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
	if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}

	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ecdh) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	if (SSL_CTX_set_tmp_ecdh (ctx, ecdh) != 1) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	EC_KEY_free(ecdh);
}

void print_certs(SSL* ssl) {
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL) {
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	} else
		printf("No certificates.\n");
}

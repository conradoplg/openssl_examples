#ifndef TLS_COMMON_H_
#define TLS_COMMON_H_

#include <openssl/ssl.h>


#define CIPHER_LIST \
	"ECDHE-RSA-AES128-GCM-SHA256:"\
	"ECDHE-ECDSA-AES128-GCM-SHA256:"\
	"ECDHE-RSA-AES256-GCM-SHA384:"\
	"ECDHE-ECDSA-AES256-GCM-SHA384:"\
	"ECDHE-RSA-AES128-SHA256:"\
	"ECDHE-ECDSA-AES128-SHA256:"\
	"ECDHE-RSA-AES128-SHA:"\
	"ECDHE-ECDSA-AES128-SHA:"\
	"ECDHE-RSA-AES256-SHA384:"\
	"ECDHE-ECDSA-AES256-SHA384:"\
	"ECDHE-RSA-AES256-SHA:"\
	"ECDHE-ECDSA-AES256-SHA:"

void print_ciphers(SSL *ssl);
void print_certs(SSL* ssl);

void ssl_setup(SSL_CTX* ctx, char *ca_file, char* cert_file, char* key_file);


#endif /* TLS_COMMON_H_ */

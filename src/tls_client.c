#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls_common.h"

int client_socket_new(const char *hostname, int port) {
	int sd;
	struct addrinfo hints;
	struct addrinfo *addr_info;
	char portstr[6];

	snprintf(portstr, sizeof(portstr), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV;

	if (getaddrinfo(hostname, portstr, &hints, &addr_info) != 0) {
		perror(NULL);
		assert(0);
	}
	sd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
	if (connect(sd, addr_info->ai_addr, addr_info->ai_addrlen) != 0) {
		perror(NULL);
		assert(0);
	}
	return sd;
}

SSL_CTX* client_new(void) {
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLSv1_2_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	return ctx;
}

int main() {
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;
	char hostname[] = "127.0.0.1";
	char portnum[] = "5000";
	char CAFile[] = "/home/conrado/ca/kryptus.crt.pem";
	char CertFile[] = "/home/conrado/ca/alice.crt.pem";
	char KeyFile[] = "/home/conrado/ca/alice.prv.pem";

	SSL_library_init();

	ctx = client_new();
	ssl_setup(ctx, CAFile, CertFile, KeyFile);
	server = client_socket_new(hostname, atoi(portnum));
	ssl = SSL_new(ctx);
	print_ciphers(ssl);
	SSL_set_fd(ssl, server);
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
	} else {
		char *msg = "Hello???";

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		print_certs(ssl);
		if (SSL_write(ssl, msg, strlen(msg)) <= 0) {
			ERR_print_errors_fp(stderr);
			assert(0);
		}
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		if (bytes <= 0) {
			ERR_print_errors_fp(stderr);
			assert(0);
		}
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);
	}
	close(server);
	SSL_CTX_free(ctx);
	return 0;
}

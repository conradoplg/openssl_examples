#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "tls_common.h"


int server_socket_new(int port) {
	int sd;
	struct sockaddr_in6 addr;
	int so_reuseaddr = 1;
	int ipv6_v6only = 0;

	sd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sd == -1) {
		perror(NULL);
		assert(0);
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) != 0) {
		perror(NULL);
		assert(0);
	}
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_v6only, sizeof(ipv6_v6only)) != 0) {
		perror(NULL);
		assert(0);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		perror(NULL);
		assert(0);
	}
	if (listen(sd, 10) != 0) {
		perror(NULL);
		assert(0);
	}
	return sd;
}

SSL_CTX* server_new(void) {
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLSv1_2_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		assert(0);
	}
	return ctx;
}

void serve_connection(SSL* ssl)
{
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* HTMLecho = "<html><body><pre>%s</pre></body></html>\n\n";
	int r1, r2;

	if ((r1 = SSL_accept(ssl)) != 1) {
		r2 = SSL_get_error(ssl, r1);
		printf("SSL_accept fail, r=%d, SSL_get_error=%d\n", r1, r2);
		ERR_print_errors_fp(stderr);
	} else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		print_certs(ssl); /* get any certificates */
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
		if (bytes > 0) {
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, HTMLecho, buf); /* construct reply */
			SSL_write(ssl, reply, strlen(reply)); /* send reply */
		} else {
			puts("No bytes read");
			ERR_print_errors_fp(stderr);
		}
	}
	sd = SSL_get_fd(ssl); /* get socket connection */
	SSL_free(ssl); /* release SSL state */
	close(sd); /* close connection */
}

int main() {
	SSL_CTX *ctx;
	int server_socket;
	char portnum[] = "5000";

	char CAFile[] = "/home/conrado/ca/kryptus.crt.pem";
	char CertFile[] = "/home/conrado/ca/server.crt.pem";
	char KeyFile[] = "/home/conrado/ca/server.prv.pem";

	SSL_library_init();
	SSL_load_error_strings();

	ctx = server_new();
	ssl_setup(ctx, CAFile, CertFile, KeyFile);
	server_socket = server_socket_new(atoi(portnum));
	while (1) {
		struct sockaddr_in6 addr;
		socklen_t len = sizeof(addr);
		char client_address_s[INET6_ADDRSTRLEN];
		SSL *ssl = NULL;
		const char *pr;

		int client = accept(server_socket, (struct sockaddr*) &addr, &len);
		if (client == -1) {
			perror(NULL);
			assert(0);
		}
		pr = inet_ntop(AF_INET6, &addr.sin6_addr, client_address_s, sizeof(client_address_s));
		if (!pr) {
			perror(NULL);
			assert(0);
		}
		printf("Connection: %s:%d\n", client_address_s, ntohs(addr.sin6_port));
		ssl = SSL_new(ctx);
		print_ciphers(ssl);
		if (!ssl) {
			ERR_print_errors_fp(stderr);
			assert(0);
		}
		if (SSL_set_fd(ssl, client) != 1) {
			ERR_print_errors_fp(stderr);
			assert(0);
		}
		serve_connection(ssl); /* service connection */
		puts("Connection served");
	}
	close(server_socket); /* close server socket */
	SSL_CTX_free(ctx); /* release context */
}

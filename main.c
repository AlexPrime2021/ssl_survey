#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#define TLS_VERSIONS_COUNT 4
/*
 * 0 - TLS ver. 1.0
 * 1 - TLS ver. 1.1
 * 2 - TLS ver. 1.2
 * 3 - TLS ver. 1.3
 */
static int tls_versions[TLS_VERSIONS_COUNT] = { 0, 1, 2, 3 };

BIO *BIO_create(SSL_CTX *ctx, char *hostname)
{
    char name[1024] = "";

    SSL *ssl;
    BIO *bio;

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    sprintf(name, "%s:%s", hostname, "443");
    BIO_set_conn_hostname(bio, name);

    return bio;
}

int pubkey_length(X509 *cert)
{
    int pubkey_length_bits = EVP_PKEY_bits(X509_get_pubkey(cert));
    printf("%i", pubkey_length_bits);
    return pubkey_length_bits;
}

void all_cipher_algorithms(SSL_CTX *ctx)
{
    STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
    int chipher_num = sk_SSL_CIPHER_num(ciphers);

    for (int i = 0; i < chipher_num; ++i)
    {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        printf(SSL_CIPHER_get_name(cipher));
        printf("\n");
    }
}

void tls_protocol_versions(char *domain)
{
    SSL_CTX *ctx;
    BIO *bio_check;

    int min_version = -1;
    int max_version = -1;

    int offset = 1;
    for (int i = 0; i < TLS_VERSIONS_COUNT; ++i)
    {
        ctx = SSL_CTX_new(TLS_method());
        SSL_CTX_set_min_proto_version(ctx, offset + i);
        SSL_CTX_set_max_proto_version(ctx, offset + i);

        bio_check = BIO_create(ctx, domain);
        if (BIO_do_connect(bio_check) > 0)
        {
            if (min_version == -1)
                min_version = offset + i;

            max_version = offset + i;
        }
    }

    BIO_free(bio_check);
    SSL_CTX_free(ctx);

    if ((min_version == -1) || (max_version == -1))
    {
	printf("Can\'t establish a connection");
	return;
    }

    printf("Min supported TLS version - TLS1.");
    printf("%i", (min_version - offset));
    printf("\n");

    printf("Max supported TLS version - TLS1.");
    printf("%i", (max_version - offset));
    printf("\n");
}

void x509_version(X509 *x509)
{
    printf("%i", (X509_get_version(x509) + 1));
}

void ssl_info(char *hostname)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    BIO *bio = BIO_create(ctx, hostname);

    if (BIO_do_connect(bio) <= 0)
    {
        printf("Can\'t establish a connection");
        return;
    }

    SSL *ssl;
    BIO_get_ssl(bio, &ssl);

    X509 *cert = SSL_get_peer_certificate(ssl);

    printf("SSL INFO");
    printf("\n\n");

    printf("Certificate version: ");
    x509_version(cert);
    printf("\n\n");

    printf("Public key length: ");
    pubkey_length(cert);
    printf("\n\n");

    printf("All cipher algorithms:");
    printf("\n");
    all_cipher_algorithms(ctx);
    printf("\n\n");

    printf("TLS supported versions:");
    printf("\n");
    tls_protocol_versions(hostname);
    printf("\n\n");

    X509_free(cert);
    SSL_free(ssl);
    BIO_free(bio);
    SSL_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    char *domain = new char[11]{ 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', '\0' };

    ssl_info(domain);

    if (domain)
        free(domain);

    return 0;
}


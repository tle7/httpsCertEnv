#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <event2/event.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>

// TODO: lots of frees probably 

struct bufferevent *handshake() {
//  every application will have an eventbase. It keeps track of all pending and active events, and notifies your application of the active ones
    struct event_base *eb = event_base_new();
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_client_method()); // specifying version is deprecated...can't do TLS 1.3?
    SSL *ssl = SSL_new(ssl_context); // have to start somewhere...
    struct bufferevent *bufev = bufferevent_openssl_socket_new(eb, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    // event_base_loop(eb);  // runs until no more events, or call break/edit
    return bufev;
}

void CAs(X509 *leaf_cert) {
    char *subject = X509_NAME_oneline(X509_get_subject_name(leaf_cert), NULL, 0); 
    // use blog code to parse fields (e.g. location)
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(leaf_cert), NULL, 0);
    printf("subject: %s\n", subject);
    OPENSSL_free(subject);
    OPENSSL_free(issuer);
}

int valid(X509 *leaf_cert) {
    int validity = X509_check_ca(leaf_cert);
    return validity; // returns error code enum I think
}

int main() {
    //OpenSSL_add_all_algorithms(); // maybe only needed for openssl 1.0
    struct bufferevent *bufev = handshake();
    SSL *ssl = bufferevent_openssl_get_ssl(bufev);
    X509 *leaf_cert = SSL_get_peer_certificate(ssl);
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl); // this may be NULL: If so, push the cert? 
    return 0;
}

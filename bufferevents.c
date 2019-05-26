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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

// TODO: lots of frees, error-catching probably 

void CAs(X509 *leaf_cert) {
    char *subject = X509_NAME_oneline(X509_get_subject_name(leaf_cert), NULL, 0); 
    // use blog code to parse fields (e.g. location)
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(leaf_cert), NULL, 0);
    printf("subject: %s\n", subject);
    OPENSSL_free(subject);
    OPENSSL_free(issuer);
}

void eventcb(struct bufferevent *bev, short events, void *ptr) {
    printf("in cb\n");
    if (events & BEV_EVENT_CONNECTED) { // this may only be for the regular bufferevent_socket_connect
    /* We're connected: start reading/writing TODO: where? */
        printf("connected!!!\n");

    } else if (events & BEV_EVENT_ERROR) {
    /* An error occured while connecting. */
        printf("error connecting :(\n");
    }   
    SSL *ssl = bufferevent_openssl_get_ssl(bev);
    X509 *leaf_cert = SSL_get_peer_certificate(ssl);
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl); // this may be NULL: If so, push the cert?
    CAs(leaf_cert);
}

struct bufferevent *handshake() {
    // every application will have an eventbase. It keeps track of all pending and active events, and notifies your application of the active ones
    // create event base
    struct event_base *eb = event_base_new();

    // setup socket
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(inet_addr("192.30.255.113")); // github 
    sin.sin_port = htons(443);

    // get initial SSL*
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_client_method()); 
    // specifying version is deprecated...can't do TLS 1.3?
    SSL *ssl = SSL_new(ssl_context); // have to start somewhere...
    struct bufferevent *bev = bufferevent_openssl_socket_new(eb, -1, ssl, 
            // TODO: make socket nonblocking w/ evutil_make_socket_nonblocking)
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS); 
    if (!bev) {
        printf("error in openssl_socket_new\n");
    }
   
    // set callback
    bufferevent_setcb(bev, NULL, NULL, eventcb, NULL);
    printf("after setting cb\n");
    // connect to socket (this makes it nonblocking)
    int fd = bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));
    if (fd < 1) { 
        /* Error starting connection */ 
        printf("error connecting to socket\n");
        bufferevent_free(bev);
        return NULL;
    } else {
        printf("connected to socket\n");
    }
    //bufferevent_setfd(bev, fd);
    event_base_dispatch(eb);
    // event_base_loop(eb);  // runs until no more events, or call break/edit
    return bev;
}



int valid(X509 *leaf_cert) {
    int validity = X509_check_ca(leaf_cert);
    return validity; // returns error code enum I think
}

int main() {
    //OpenSSL_add_all_algorithms(); // maybe only needed for openssl 1.0
    struct bufferevent *bev = handshake();
     
    return 0;
}

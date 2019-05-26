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

#include "get_tls_sites.h"

#define NUM_TLS_INS 2

// TODO: lots of frees, error-catching probably 

int verify(X509 *leaf_cert) {
    int validity = X509_check_ca(leaf_cert);
    return validity; // returns error code enum I think
}

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
    if (events & BEV_EVENT_CONNECTED) { // does this happen even if handshake fails?  
    /* We're connected: start reading/writing TODO: where? */
        printf("connected!!!\n");
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        X509 *leaf_cert = SSL_get_peer_certificate(ssl); 
        // if returns NULL, count that has handshake failure?
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl); // this may be NULL: If so, push the cert?
        verify(leaf_cert);
        CAs(leaf_cert);

    } else if (events & BEV_EVENT_ERROR) {
    /* An error occured while connecting. */
        printf("error connecting in cb\n"); // count this as handshake failure too?
        unsigned long err = bufferevent_get_openssl_error(bev);
    }  
    bufferevent_free(bev); // closes socket since close_on_free is set
    //SSL_CTX_free(ssl_context); // TODO: should do this

}

void handshake_ip(char *ip, struct event_base *base) {
     // get initial SSL*: only works if each one has their own
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_client_method()); 
    // specifying version is deprecated...can't do TLS 1.3?
    SSL *ssl = SSL_new(ssl_context); // have to start somewhere...
    // setup socket
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin)); // perhaps pre-compute this: array of sockaddrs instead of IPs?
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip); // github 
    sin.sin_port = htons(443);

    struct bufferevent *bev = bufferevent_openssl_socket_new(base, -1, ssl, 
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS); 
    if (!bev) {
        printf("error in openssl_socket_new with ip %s\n", ip);
    }
   
    // set callback
    bufferevent_setcb(bev, NULL, NULL, eventcb, NULL);
    printf("after setting cb\n");
    // connect to socket (this makes it nonblocking)
    int fd = bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));
    if (fd == -1) { // returns 0 on success 
        /* Error starting connection */ 
        printf("error connecting to socket with ip %s\n", ip);
    } else {
        printf("connected to socket with ip %s\n", ip);
    }
}

void handshake(struct sockaddr_in *sin, struct event_base *base) {
     // get initial SSL*: only works if each one has their own
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_client_method()); 
    // specifying version is deprecated...can't do TLS 1.3?
    SSL *ssl = SSL_new(ssl_context); // have to start somewhere...
    // setup socket
    /*
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin)); // perhaps pre-compute this: array of sockaddrs instead of IPs?
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip); // github 
    sin.sin_port = htons(443);
    */
    struct bufferevent *bev = bufferevent_openssl_socket_new(base, -1, ssl, 
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS); 
    if (!bev) {
        printf("error in openssl_socket_new with ip\n");
    }
   
    // set callback
    bufferevent_setcb(bev, NULL, NULL, eventcb, NULL);
    printf("after setting cb\n");
    // connect to socket (this makes it nonblocking)
    int fd = bufferevent_socket_connect(bev, (struct sockaddr*) sin, sizeof(sin));
    if (fd == -1) { // returns 0 on success 
        /* Error starting connection */ 
        printf("error connecting to socket with ip\n");
    } else {
        printf("connected to socket with ip\n");
    }
}


int main() {
    //OpenSSL_add_all_algorithms(); // maybe only needed for openssl 1.0
    
    char *ips[] = {"192.30.255.113","143.204.129.163" }; // github, slack (google requires SNI)
    //char *ips[] = {"192.30.255.113"}; 
    size_t n_ips = sizeof(ips)/sizeof(ips[0]);
    // create event base
    struct event_base *base_ip = event_base_new();

    for (int i = 0; i < n_ips; i++) {
        handshake_ip(ips[i], base_ip);
    }
        //bufferevent_setfd(bev, fd); // TODO
    event_base_dispatch(base_ip);
    // event_base_loop(base);  // runs until no more events, or call break/edit
    event_base_free(base_ip);
   
    //test new array of struct sockaddr 
    struct sockaddr_in* in_arr = get_tls_sites(NUM_TLS_INS);
    // create event base
    struct event_base *base = event_base_new();

    for (int i = 0; i < NUM_TLS_INS; i++) {
        handshake(&in_arr[i], base);
    }
        //bufferevent_setfd(bev, fd); // TODO
    event_base_dispatch(base);
    // event_base_loop(base);  // runs until no more events, or call break/edit
    event_base_free(base);
    return 0;
}

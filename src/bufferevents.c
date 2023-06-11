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
#include "hash.h"
#include <assert.h>
#define NUM_TLS_INS 900


typedef struct {
    const char *name; // malloc
    size_t nsigned;
    struct hash_elem hash_elem;
} CA;

struct hash *CAs;

static int next_i = 0;
static X509_STORE *store;
static size_t nhandshakes = 0;
static size_t ntrusted = 0;

// TODO: lots of frees, error-catching probably 
void handshake(struct sockaddr_in *sin, struct event_base *base);

unsigned CA_hash(const struct hash_elem *elem, void *aux) {
    const CA *ca = hash_entry (elem, CA, hash_elem);
    return hash_string (ca->name);
}

bool CA_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux) {
    const CA *a = hash_entry (a_, CA, hash_elem);
    const CA *b = hash_entry (b_, CA, hash_elem);

    return strcmp(a->name, b->name) < 0;
}

void CA_print(struct hash_elem *a, void *aux) {
    CA *ca = hash_entry(a, CA, hash_elem);
    printf("%s: %zu\n", ca->name, ca->nsigned);
}


// adds new CA or increments nsigned for existing one
void insert_CA(const char *name) { 
    CA *new_CA = malloc(sizeof(CA));
    assert(new_CA);
    new_CA->name = name;
    new_CA->nsigned = 1;
    struct hash_elem *found = hash_insert(CAs, &new_CA->hash_elem); // returns NULL if not found/inserted
    if (found) {
        new_CA->nsigned = hash_entry(found, CA, hash_elem)->nsigned + 1; // increment nsigned
        hash_replace(CAs, &new_CA->hash_elem);
    } 
    // hash_apply(CAs, CA_print); // tested
}

const char *get_validation_errstr(long e) {
	switch ((int) e) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT";
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "ERR_UNABLE_TO_GET_CRL";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "ERR_CERT_SIGNATURE_FAILURE";
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "ERR_CRL_SIGNATURE_FAILURE";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "ERR_CERT_NOT_YET_VALID";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "ERR_CERT_HAS_EXPIRED";
		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "ERR_CRL_NOT_YET_VALID";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "ERR_CRL_HAS_EXPIRED";
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
		case X509_V_ERR_OUT_OF_MEM:
			return "ERR_OUT_OF_MEM";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "ERR_CERT_CHAIN_TOO_LONG";
		case X509_V_ERR_CERT_REVOKED:
			return "ERR_CERT_REVOKED";
		case X509_V_ERR_INVALID_CA:
			return "ERR_INVALID_CA";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "ERR_PATH_LENGTH_EXCEEDED";
		case X509_V_ERR_INVALID_PURPOSE:
			return "ERR_INVALID_PURPOSE";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "ERR_CERT_UNTRUSTED";
		case X509_V_ERR_CERT_REJECTED:
			return "ERR_CERT_REJECTED";
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			return "ERR_SUBJECT_ISSUER_MISMATCH";
		case X509_V_ERR_AKID_SKID_MISMATCH:
			return "ERR_AKID_SKID_MISMATCH";
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			return "ERR_KEYUSAGE_NO_CERTSIGN";
		case X509_V_ERR_INVALID_EXTENSION:
			return "ERR_INVALID_EXTENSION";
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
			return "ERR_INVALID_POLICY_EXTENSION";
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			return "ERR_NO_EXPLICIT_POLICY";
		case X509_V_ERR_APPLICATION_VERIFICATION:
			return "ERR_APPLICATION_VERIFICATION";
		default:
			return "ERR_UNKNOWN";
	}
}

X509_STORE *create_store() {
    store = X509_STORE_new();
    if (store == NULL) {
        printf("unable to create new X509 store.\n");
        return NULL;
    }
    char *store_path = "/etc/ssl/certs/ca-certificates.crt"; 
    int rc = X509_STORE_load_locations(store, store_path, NULL);
    if (rc != 1) {
        printf("unable to load certificates at %s to store\n", store_path);
        X509_STORE_free(store);
        return NULL;
    }
    return store;
}

void verify(SSL *ssl, X509 *leaf_cert) {
    // must get new ctx for each call to verify (or cleanup old ctx)
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "unable to create STORE CTX\n"); // record this as error
        return;
    }
                        
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl); 
    if (!chain) {
        chain = sk_X509_new_null();
        sk_X509_push(chain, leaf_cert);
    }
        
    int rc = X509_STORE_CTX_init(ctx, store, leaf_cert, chain);
    if (rc != 1) {
        fprintf(stderr, "unable to initialize STORE CTX.\n");
        X509_STORE_CTX_free(ctx);
        return;
    }
    int ret = X509_verify_cert(ctx); // 1 if valid, 0 if not, < 0 if error
    if (ret < 0) {
        printf("error in verify \n");
    } else if (ret == 1) {
        printf("VALID CERT\n");
        ntrusted++; 
    } else {
        int err = X509_STORE_CTX_get_error(ctx); // tested with google 
        printf("%s\n", get_validation_errstr(err)); // TODO: record reason
    }

    X509_STORE_CTX_free(ctx);
}

void record_CAs(X509 *leaf_cert) {
    char *subject = X509_NAME_oneline(X509_get_subject_name(leaf_cert), NULL, 0); 
    // use blog code to parse fields (e.g. location)
    //char *issuer = X509_NAME_oneline(X509_get_issuer_name(leaf_cert), NULL, 0);
    X509_NAME *issuer_full = X509_get_issuer_name(leaf_cert);
    X509_NAME_ENTRY *issuer_O = X509_NAME_get_entry(issuer_full, 1); // TODO: check for <2 entries
    ASN1_STRING *d = X509_NAME_ENTRY_get_data(issuer_O);
	const char *issuer = strdup(ASN1_STRING_get0_data(d)); 
    // printf("issuer: %s\n", issuer);
    insert_CA(issuer);
    OPENSSL_free(subject);
    // TODO: what needs to be freed in this ridiculous interface
}

void eventcb(struct bufferevent *bev, short events, void *ptr) {
    printf("in cb\n");
    if (events & BEV_EVENT_CONNECTED) { // does this happen even if handshake fails?  
        printf("connected!!!\n");
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        X509 *leaf_cert = SSL_get_peer_certificate(ssl); 
        nhandshakes++;
        // if returns NULL, count that has handshake failure?
        verify(ssl, leaf_cert);
        record_CAs(leaf_cert);

    } else if (events & BEV_EVENT_ERROR) {
    /* An error occured while connecting. */
        printf("error connecting in cb\n"); // count this as handshake failure too?
        unsigned long err = bufferevent_get_openssl_error(bev);
    } // TODO: need to handle other possibilities? also impose timeout 
    //SSL_CTX_free(ssl_context); // TODO: should do this
    
    // next connection
    struct event_base *base = bufferevent_get_base(bev);
    bufferevent_free(bev); // closes socket since close_on_free is set
    // handshake("143.204.129.163", base);  // TODO: next one in array (this seems to work)
}

void handshake(struct sockaddr_in *sin, struct event_base *base) {
     // get initial SSL*: only works if each one has their own
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_client_method()); 
    // specifying version is deprecated...can't do TLS 1.3?
    SSL *ssl = SSL_new(ssl_context); // have to start somewhere...
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
    int fd = bufferevent_socket_connect(bev, (struct sockaddr*) sin, sizeof(struct sockaddr_in));
    if (fd == -1) { // returns 0 on success 
        /* Error starting connection */ 
        printf("error connecting to socket with ip\n");
    } else {
        printf("connected to socket with ip\n");
    }
}

int main() {
    //OpenSSL_add_all_algorithms(); // maybe only needed for openssl 1.0
    
    //char *ips[] = {"192.30.255.113","143.204.129.163" }; // github, slack 
    //char *ips[] = {"192.30.255.113"}; 
    char *ips[] = {"172.217.6.78","192.30.255.113"}; // google (requires SNI),  github
    size_t num_sites = sizeof(ips) / sizeof(ips[0]);

    //struct sockaddr_in* in_arr = get_tls_sites(NUM_TLS_INS);
    struct sockaddr_in* in_arr = calloc(num_sites, sizeof(struct sockaddr_in));

    for (int i = 0; i < num_sites; i++) {
        in_arr[i].sin_family = AF_INET;
        in_arr[i].sin_port = htons(443);
        in_arr[i].sin_addr.s_addr = inet_addr(ips[i]);
    }

    // init CA hash table
    CAs = malloc (sizeof (struct hash));
    assert(CAs);
    hash_init(CAs, CA_hash, CA_less, NULL);
    // create event base
    struct event_base *base = event_base_new();

    // create cert store
    if (!create_store()) {
        return -1;
    }

    // do initial 2500 handshakes
    //for (int i = 0; i < NUM_TLS_INS; i++) {
  
    for (int i = 0; i < num_sites; i++) {
        handshake(&in_arr[i], base);
    }
    event_base_dispatch(base);

    // event_base_loop(base);  // runs until no more events, or call break/edit
    event_base_free(base);
    // TODO: free hash table (and its names)
    return 0;
}

/* The POSIX socket API (getaddrinfo, struct timeval...) is hidden by a strict
 * -std=c11, which is how Squaero builds this; ask for it by name. */
#if !defined(_WIN32)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#    define _DARWIN_C_SOURCE
#  endif
#endif

#include "mywire.h"

#include "proto.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define BAD_SOCK INVALID_SOCKET
#define sock_close closesocket
#define SEND_FLAGS 0
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int sock_t;
#define BAD_SOCK (-1)
#define sock_close close
#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL /* a closed peer must not kill the process */
#else
#define SEND_FLAGS 0 /* Apple: SO_NOSIGPIPE on the socket instead */
#endif
#endif

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define MAX_REPLY (1u << 30) /* the server's own max_allowed_packet ceiling */
#define NOT_NULL ((size_t)-1)

struct mw_conn {
    sock_t s;
    SSL_CTX *ctx;
    SSL *ssl; /* NULL on a plain connection */
    unsigned seq;
    mw_buf pkt; /* payload of the last packet read */
    char err[512];
    unsigned errnum;
    char sqlstate[6];
    int timeout_ms; /* while connecting; 0 once connected */
    int lost;
    unsigned status;
    unsigned long thread_id;
    char version[64];
    mw_result *open; /* the result whose rows are still arriving */
    int pending;     /* more results follow the one just ended */
    mw_options o;    /* copies, for mw_cancel's second connection */
};

struct mw_result {
    mw_conn *c;
    mw_coldef *defs;
    mw_column *cols;
    int ncols;
    int ended;
    int have_row;
    mw_buf cells;
    size_t *off, *len;
    unsigned long long affected, insert_id;
};

static int fail(mw_conn *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof c->err, fmt, ap);
    va_end(ap);
    c->errnum = 0;
    memcpy(c->sqlstate, "00000", 6);
    return -1;
}

static int lose(mw_conn *c, const char *what)
{
    c->lost = 1;
    return fail(c, "%s", what);
}

static int server_err(mw_conn *c)
{
    mw_err e;
    if (mw_parse_err(c->pkt.p, c->pkt.n, &e) < 0)
        return lose(c, "unreadable error packet from the server");
    snprintf(c->err, sizeof c->err, "%s", e.message);
    c->errnum = e.code;
    memcpy(c->sqlstate, e.sqlstate, 6);
    return -1;
}

/* ---- socket -------------------------------------------------------- */

static int send_all(mw_conn *c, const uint8_t *p, size_t n)
{
    while (n) {
        int chunk = (int)(n > 0x10000 ? 0x10000 : n);
        int k = c->ssl ? SSL_write(c->ssl, p, chunk)
                       : (int)send(c->s, (const char *)p, chunk, SEND_FLAGS);
        if (k <= 0)
            return lose(c, "connection lost while sending");
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

static int recv_all(mw_conn *c, uint8_t *p, size_t n)
{
    while (n) {
        int chunk = (int)(n > 0x10000 ? 0x10000 : n);
        int k = c->ssl ? SSL_read(c->ssl, p, chunk) : (int)recv(c->s, (char *)p, chunk, 0);
        if (k <= 0) {
            if (c->timeout_ms && k == 0)
                return lose(c, "the server closed the connection while logging in");
            if (c->timeout_ms)
                return lose(c, "no answer from the server while logging in");
            return lose(c, "connection closed by the server");
        }
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

/* Receive and send timeout in milliseconds, 0 = none. */
static void set_timeout(sock_t s, int ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)ms;
#else
    struct timeval t;
    t.tv_sec = ms / 1000;
    t.tv_usec = (ms % 1000) * 1000;
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
}

static sock_t dial(const char *host, int port)
{
    struct addrinfo hints, *res, *ai;
    char svc[16];
    sock_t s = BAD_SOCK;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(svc, sizeof svc, "%d", port);
    if (getaddrinfo(host, svc, &hints, &res) != 0)
        return BAD_SOCK;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK)
            continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        sock_close(s);
        s = BAD_SOCK;
    }
    freeaddrinfo(res);
    if (s != BAD_SOCK) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
#ifdef SO_NOSIGPIPE
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&one, sizeof one);
#endif
    }
    return s;
}

/* ---- packets -------------------------------------------------------- */

/* Read one packet, joining the 16 MB pieces of a larger one, into c->pkt. */
static int read_packet(mw_conn *c)
{
    size_t len;
    c->pkt.n = 0;
    do {
        uint8_t h[4];
        if (recv_all(c, h, 4) < 0)
            return -1;
        len = (size_t)h[0] | (size_t)h[1] << 8 | (size_t)h[2] << 16;
        if (h[3] != (uint8_t)c->seq)
            return lose(c, "packet out of sequence from the server");
        c->seq = (c->seq + 1) & 0xFF;
        if (c->pkt.n + len > MAX_REPLY)
            return lose(c, "the server sent a packet over 1 GB");
        if (c->pkt.n + len + 1 > c->pkt.cap) {
            size_t cap = c->pkt.n + len + 1;
            uint8_t *p = (uint8_t *)realloc(c->pkt.p, cap);
            if (!p)
                return lose(c, "out of memory");
            c->pkt.p = p;
            c->pkt.cap = cap;
        }
        if (recv_all(c, c->pkt.p + c->pkt.n, len) < 0)
            return -1;
        c->pkt.n += len;
    } while (len == 0xFFFFFF);
    return 0;
}

static int write_packet(mw_conn *c, const uint8_t *p, size_t n)
{
    size_t chunk;
    do {
        uint8_t h[4];
        chunk = n < 0xFFFFFF ? n : 0xFFFFFF;
        h[0] = (uint8_t)chunk;
        h[1] = (uint8_t)(chunk >> 8);
        h[2] = (uint8_t)(chunk >> 16);
        h[3] = (uint8_t)c->seq;
        c->seq = (c->seq + 1) & 0xFF;
        if (send_all(c, h, 4) < 0 || send_all(c, p, chunk) < 0)
            return -1;
        p += chunk;
        n -= chunk;
    } while (chunk == 0xFFFFFF); /* a piece of exactly 16 MB is followed by one more */
    return 0;
}

static int write_buf(mw_conn *c, mw_buf *b)
{
    int rc = b->oom ? fail(c, "out of memory") : write_packet(c, b->p, b->n);
    buf_free(b);
    return rc;
}

/* ---- TLS ----------------------------------------------------------- */

static int tls_fail(mw_conn *c, const char *what)
{
    unsigned long e = ERR_get_error();
    long v = c->ssl ? SSL_get_verify_result(c->ssl) : X509_V_OK;
    char buf[256];
    if (v != X509_V_OK)
        return fail(c, "%s: server certificate rejected: %s", what,
                    X509_verify_cert_error_string(v));
    if (e) {
        ERR_error_string_n(e, buf, sizeof buf);
        return fail(c, "%s: %s", what, buf);
    }
    return fail(c, "%s failed", what);
}

static int is_ip(const char *host)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return 0;
    freeaddrinfo(res);
    return 1;
}

static int tls_start(mw_conn *c, const mw_options *o)
{
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx)
        return tls_fail(c, "TLS setup");
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    if (o->tls >= MW_TLS_VERIFY_CA) {
        int ok = o->ca_file ? SSL_CTX_load_verify_locations(c->ctx, o->ca_file, NULL)
                            : SSL_CTX_set_default_verify_paths(c->ctx);
        if (ok != 1)
            return fail(c, "cannot load the CA file %s", o->ca_file ? o->ca_file : "(default)");
        SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    }
    if (o->cert_file &&
        (SSL_CTX_use_certificate_chain_file(c->ctx, o->cert_file) != 1 ||
         SSL_CTX_use_PrivateKey_file(c->ctx, o->key_file ? o->key_file : o->cert_file,
                                     SSL_FILETYPE_PEM) != 1))
        return tls_fail(c, "loading the client certificate");
    c->ssl = SSL_new(c->ctx);
    if (!c->ssl || SSL_set_fd(c->ssl, (int)c->s) != 1)
        return tls_fail(c, "TLS setup");
    if (!is_ip(o->host))
        SSL_set_tlsext_host_name(c->ssl, o->host);
    if (o->tls == MW_TLS_VERIFY_FULL) {
        int ok = is_ip(o->host) ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(c->ssl), o->host)
                                : SSL_set1_host(c->ssl, o->host);
        if (ok != 1)
            return tls_fail(c, "TLS setup");
    }
    if (SSL_connect(c->ssl) != 1)
        return tls_fail(c, "TLS handshake");
    return 0;
}

/* ---- logging in ---------------------------------------------------- */

static const char NATIVE[] = "mysql_native_password";
static const char SHA2[] = "caching_sha2_password";

/* The first answer of plugin to nonce; -1 if the plugin is not supported. */
static int auth_data(const char *plugin, const char *pw, const uint8_t nonce[20], uint8_t out[32])
{
    if (!strcmp(plugin, NATIVE)) {
        if (!*pw)
            return 0;
        mw_scramble_native(pw, nonce, out);
        return 20;
    }
    if (!strcmp(plugin, SHA2)) {
        if (!*pw)
            return 0;
        mw_scramble_sha2(pw, nonce, out);
        return 32;
    }
    return -1;
}

/* caching_sha2_password's full authentication without TLS: the password,
 * NUL-terminated and XORed with the nonce, encrypted with the server's
 * public key (RSA OAEP). */
static int send_rsa(mw_conn *c, const char *pw, const uint8_t nonce[20])
{
    BIO *bio = BIO_new_mem_buf(c->pkt.p + 1, (int)c->pkt.n - 1);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY_CTX *x = key ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    size_t n = strlen(pw) + 1, outlen = 0, i;
    uint8_t *in = (uint8_t *)malloc(n), *out = NULL;
    int rc = -1;
    if (in && x && EVP_PKEY_encrypt_init(x) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(x, RSA_PKCS1_OAEP_PADDING) == 1) {
        for (i = 0; i < n; i++)
            in[i] = (uint8_t)((i + 1 < n ? (uint8_t)pw[i] : 0) ^ nonce[i % 20]);
        if (EVP_PKEY_encrypt(x, NULL, &outlen, in, n) == 1 &&
            (out = (uint8_t *)malloc(outlen)) != NULL &&
            EVP_PKEY_encrypt(x, out, &outlen, in, n) == 1)
            rc = write_packet(c, out, outlen);
        else
            fail(c, "cannot encrypt the password with the server's public key");
    } else {
        fail(c, "the server sent an unreadable public key");
    }
    free(in);
    free(out);
    EVP_PKEY_CTX_free(x);
    EVP_PKEY_free(key);
    BIO_free(bio);
    return rc;
}

static int login(mw_conn *c, const mw_handshake *h, uint32_t caps, const mw_options *o)
{
    const char *pw = o->password ? o->password : "";
    char plugin[64];
    uint8_t nonce[20], data[32];
    int n;
    mw_buf b = {0};

    /* A plugin we do not know may still be switched to one we do. */
    snprintf(plugin, sizeof plugin, "%s",
             auth_data(h->plugin, pw, h->nonce, data) < 0 ? NATIVE : h->plugin);
    memcpy(nonce, h->nonce, 20);
    n = auth_data(plugin, pw, nonce, data);

    buf_le32(&b, caps);
    buf_le32(&b, MW_MAX_PACKET);
    buf_u8(&b, MW_CHARSET_UTF8MB4);
    buf_put(&b, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 23);
    buf_put(&b, o->user, strlen(o->user) + 1);
    if (caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
        buf_lenenc(&b, (uint64_t)n);
    else
        buf_u8(&b, (unsigned)n);
    buf_put(&b, data, (size_t)n);
    if (caps & CLIENT_CONNECT_WITH_DB)
        buf_put(&b, o->database, strlen(o->database) + 1);
    if (caps & CLIENT_PLUGIN_AUTH)
        buf_put(&b, plugin, strlen(plugin) + 1);
    if (write_buf(c, &b) < 0)
        return -1;

    for (;;) {
        const uint8_t *p;
        if (read_packet(c) < 0)
            return -1;
        p = c->pkt.p;
        if (!c->pkt.n)
            return lose(c, "empty packet while logging in");
        if (p[0] == 0x00) {
            mw_ok ok;
            if (mw_parse_ok(p, c->pkt.n, &ok) < 0)
                return lose(c, "unreadable OK packet");
            c->status = ok.status;
            return 0;
        }
        if (p[0] == 0xFF)
            return server_err(c);
        if (p[0] == 0xFE) { /* AuthSwitchRequest: another plugin, a new nonce */
            mw_rd r = {p + 1, c->pkt.n - 1, 0};
            const uint8_t *nn;
            if (!rd_cstr(&r, plugin, sizeof plugin))
                return fail(c, "the server asks for the pre-4.1 password protocol, not supported");
            nn = rd_bytes(&r, 20);
            if (!nn)
                return lose(c, "unreadable authentication switch");
            memcpy(nonce, nn, 20);
            n = auth_data(plugin, pw, nonce, data);
            if (n < 0)
                return fail(c, "authentication plugin %s is not supported", plugin);
            if (write_packet(c, data, (size_t)n) < 0)
                return -1;
            continue;
        }
        if (p[0] == 0x01 && c->pkt.n >= 2 && !strcmp(plugin, SHA2)) {
            if (p[1] == 0x03) /* fast authentication: the OK follows */
                continue;
            if (p[1] != 0x04)
                return lose(c, "unexpected caching_sha2_password reply");
            /* Full authentication: over TLS the password goes as is. */
            if (c->ssl) {
                if (write_packet(c, (const uint8_t *)pw, strlen(pw) + 1) < 0)
                    return -1;
                continue;
            }
            {
                static const uint8_t ask_key = 0x02;
                if (write_packet(c, &ask_key, 1) < 0 || read_packet(c) < 0)
                    return -1;
            }
            if (c->pkt.n < 2 || c->pkt.p[0] != 0x01)
                return c->pkt.n && c->pkt.p[0] == 0xFF ? server_err(c)
                                                       : lose(c, "the server sent no public key");
            if (send_rsa(c, pw, nonce) < 0)
                return -1;
            continue;
        }
        return lose(c, "unexpected reply while logging in");
    }
}

static char *dup(const char *s)
{
    char *d;
    if (!s)
        return NULL;
    d = (char *)malloc(strlen(s) + 1);
    if (d)
        strcpy(d, s);
    return d;
}

static void free_opts(mw_options *o)
{
    free((char *)o->host);
    free((char *)o->user);
    free((char *)o->password);
    free((char *)o->database);
    free((char *)o->ca_file);
    free((char *)o->cert_file);
    free((char *)o->key_file);
}

mw_conn *mw_connect(const mw_options *o, char *err, int errlen)
{
    mw_conn *c = (mw_conn *)calloc(1, sizeof *c);
    mw_handshake h;
    uint32_t caps;
    int port;
#ifdef _WIN32
    WSADATA wsa;
#endif
    if (!c) {
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }
    c->s = BAD_SOCK;
    memcpy(c->sqlstate, "00000", 6);
#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    c->o = *o;
    c->o.host = dup(o->host ? o->host : "localhost");
    c->o.user = dup(o->user ? o->user : "");
    c->o.password = dup(o->password);
    c->o.database = o->database && *o->database ? dup(o->database) : NULL;
    c->o.ca_file = dup(o->ca_file);
    c->o.cert_file = dup(o->cert_file);
    c->o.key_file = dup(o->key_file);
    o = &c->o;
    if (!o->host || !o->user) {
        fail(c, "out of memory");
        goto out;
    }
    port = o->port > 0 ? o->port : 3306;
    c->s = dial(o->host, port);
    if (c->s == BAD_SOCK) {
        fail(c, "cannot connect to %s:%d", o->host, port);
        goto out;
    }
    c->timeout_ms = o->connect_timeout_ms > 0 ? o->connect_timeout_ms : 30000;
    set_timeout(c->s, c->timeout_ms);

    if (read_packet(c) < 0)
        goto out;
    if (c->pkt.n && c->pkt.p[0] == 0xFF) { /* e.g. host not allowed, too many connections */
        server_err(c);
        goto out;
    }
    if (mw_parse_handshake(c->pkt.p, c->pkt.n, &h) < 0) {
        fail(c, "%s:%d is not a MySQL or MariaDB server", o->host, port);
        goto out;
    }
    if (!(h.caps & CLIENT_PROTOCOL_41) || !(h.caps & CLIENT_SECURE_CONNECTION)) {
        fail(c, "server %s is too old (it lacks the 4.1 protocol)", h.version);
        goto out;
    }
    c->thread_id = h.thread_id;
    snprintf(c->version, sizeof c->version, "%s", h.version);
    caps = CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS |
           CLIENT_SECURE_CONNECTION | CLIENT_MULTI_RESULTS | CLIENT_PLUGIN_AUTH |
           CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | (o->database ? CLIENT_CONNECT_WITH_DB : 0);
    caps &= h.caps;

    if (o->tls != MW_TLS_OFF && !(h.caps & CLIENT_SSL) && o->tls != MW_TLS_PREFER) {
        fail(c, "TLS was requested but the server does not support it");
        goto out;
    }
    if (o->tls != MW_TLS_OFF && (h.caps & CLIENT_SSL)) {
        mw_buf b = {0};
        caps |= CLIENT_SSL;
        buf_le32(&b, caps); /* SSLRequest: the response's first 32 bytes */
        buf_le32(&b, MW_MAX_PACKET);
        buf_u8(&b, MW_CHARSET_UTF8MB4);
        buf_put(&b, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 23);
        if (write_buf(c, &b) < 0 || tls_start(c, o) < 0)
            goto out;
    }
    if (login(c, &h, caps, o) < 0)
        goto out;
    set_timeout(c->s, 0); /* a long query must not time out */
    c->timeout_ms = 0;
    return c;

out:
    if (err && errlen > 0)
        snprintf(err, (size_t)errlen, "%s", c->err);
    mw_close(c);
    return NULL;
}

void mw_close(mw_conn *c)
{
    if (!c)
        return;
    if (c->s != BAD_SOCK && !c->lost && !c->open) {
        static const uint8_t quit = 0x01; /* COM_QUIT: the server logs no aborted connection */
        c->seq = 0;
        write_packet(c, &quit, 1);
    }
    if (c->ssl)
        SSL_free(c->ssl);
    if (c->ctx)
        SSL_CTX_free(c->ctx);
    if (c->s != BAD_SOCK)
        sock_close(c->s);
#ifdef _WIN32
    WSACleanup();
#endif
    buf_free(&c->pkt);
    free_opts(&c->o);
    free(c);
}

const char *mw_error(const mw_conn *c) { return c->err; }
unsigned mw_errno(const mw_conn *c) { return c->errnum; }
const char *mw_sqlstate(const mw_conn *c) { return c->sqlstate; }
int mw_conn_lost(const mw_conn *c) { return c->lost; }
unsigned long mw_thread_id(const mw_conn *c) { return c->thread_id; }
const char *mw_server_version(const mw_conn *c) { return c->version; }
const char *mw_tls_cipher(const mw_conn *c) { return c->ssl ? SSL_get_cipher(c->ssl) : NULL; }

size_t mw_escape(const mw_conn *c, char *to, const char *from, size_t len)
{
    return mw_escape_str(to, from, len, (c->status & SERVER_NO_BACKSLASH_ESCAPES) != 0);
}

int mw_cancel(mw_conn *c)
{
    mw_options o = c->o;
    mw_conn *k;
    mw_result *r = NULL;
    char sql[48];
    int rc;
    if (o.tls == MW_TLS_PREFER && !c->ssl)
        o.tls = MW_TLS_OFF;
    k = mw_connect(&o, NULL, 0);
    if (!k)
        return -1;
    snprintf(sql, sizeof sql, "KILL QUERY %lu", c->thread_id);
    rc = mw_query(k, sql, strlen(sql), &r);
    mw_free(r);
    mw_close(k);
    return rc;
}

/* ---- queries ------------------------------------------------------- */

static void result_free(mw_result *r)
{
    if (!r)
        return;
    if (r->c->open == r)
        r->c->open = NULL;
    free(r->defs);
    free(r->cols);
    free(r->off);
    free(r->len);
    buf_free(&r->cells);
    free(r);
}

/* Read a statement's response up to its rows (or to its end if it has
 * none). An OK flagged with more results is skipped for what follows. */
static int read_head(mw_conn *c, mw_result *r)
{
    for (;;) {
        const uint8_t *p;
        mw_rd rd;
        uint64_t n;
        int i;
        if (read_packet(c) < 0)
            return -1;
        p = c->pkt.p;
        if (!c->pkt.n)
            return lose(c, "empty reply from the server");
        if (p[0] == 0x00) {
            mw_ok ok;
            if (mw_parse_ok(p, c->pkt.n, &ok) < 0)
                return lose(c, "unreadable OK packet");
            c->status = ok.status;
            r->affected = ok.affected;
            r->insert_id = ok.insert_id;
            if (ok.status & SERVER_MORE_RESULTS_EXISTS)
                continue;
            r->ended = 1;
            return 0;
        }
        if (p[0] == 0xFF)
            return server_err(c);
        if (p[0] == 0xFB) {
            /* LOAD DATA LOCAL: we never offer CLIENT_LOCAL_FILES, but a server
             * may ask anyway; an empty packet declines it. */
            static const uint8_t none = 0;
            if (write_packet(c, &none, 0) < 0 || read_packet(c) < 0)
                return -1;
            return fail(c, "LOAD DATA LOCAL INFILE is not supported");
        }
        rd.p = p;
        rd.n = c->pkt.n;
        rd.bad = 0;
        n = rd_lenenc(&rd, NULL);
        if (rd.bad || n == 0 || n > 4096)
            return lose(c, "unreadable result header");
        r->ncols = (int)n;
        r->defs = (mw_coldef *)calloc(n, sizeof *r->defs);
        r->cols = (mw_column *)calloc(n, sizeof *r->cols);
        r->off = (size_t *)calloc(n, sizeof *r->off);
        r->len = (size_t *)calloc(n, sizeof *r->len);
        if (!r->defs || !r->cols || !r->off || !r->len)
            return lose(c, "out of memory");
        for (i = 0; i < r->ncols; i++) {
            mw_coldef *d = &r->defs[i];
            if (read_packet(c) < 0)
                return -1;
            if (mw_parse_coldef(c->pkt.p, c->pkt.n, d) < 0)
                return lose(c, "unreadable column definition");
            r->cols[i].name = d->name;
            r->cols[i].type = d->type;
            r->cols[i].flags = d->flags;
            r->cols[i].charset = d->charset;
            r->cols[i].length = d->length;
            r->cols[i].decimals = d->decimals;
        }
        if (read_packet(c) < 0)
            return -1;
        if (!mw_is_eof(c->pkt.p, c->pkt.n))
            return lose(c, "no end of the column definitions");
        c->open = r;
        return 0;
    }
}

/* Skip the results left after the one handed out (a CALL's final OK). */
static int drain(mw_conn *c)
{
    while (c->pending && !c->lost) {
        mw_result *r = (mw_result *)calloc(1, sizeof *r);
        int rc;
        if (!r)
            return lose(c, "out of memory");
        r->c = c;
        c->pending = 0;
        rc = read_head(c, r);
        while (rc == 0 && !r->ended)
            rc = mw_next(r) < 0 ? -1 : 0;
        result_free(r);
        if (rc < 0)
            return -1;
    }
    return c->lost ? -1 : 0;
}

int mw_query(mw_conn *c, const char *sql, size_t len, mw_result **out)
{
    mw_result *r;
    mw_buf b = {0};
    *out = NULL;
    if (c->lost)
        return fail(c, "the connection was lost");
    if (c->open)
        return fail(c, "the previous result is still open: fetch it to the end or free it");
    if (c->pending && drain(c) < 0)
        return -1;
    c->err[0] = 0;
    c->errnum = 0;
    memcpy(c->sqlstate, "00000", 6);
    r = (mw_result *)calloc(1, sizeof *r);
    if (!r)
        return fail(c, "out of memory");
    r->c = c;
    c->seq = 0;
    buf_u8(&b, 0x03); /* COM_QUERY */
    buf_put(&b, sql, len);
    if (write_buf(c, &b) < 0 || read_head(c, r) < 0) {
        result_free(r);
        return -1;
    }
    *out = r;
    return 0;
}

int mw_col_count(const mw_result *r) { return r->ncols; }

const mw_column *mw_col(const mw_result *r, int col)
{
    return col >= 0 && col < r->ncols ? &r->cols[col] : NULL;
}

int mw_next(mw_result *r)
{
    mw_conn *c;
    mw_rd rd;
    int i;
    if (!r || r->ended)
        return 0;
    c = r->c;
    r->have_row = 0;
    if (c->lost || read_packet(c) < 0) {
        if (c->lost && !c->err[0])
            fail(c, "the connection was lost");
        r->ended = 1;
        c->open = NULL;
        return -1;
    }
    if (mw_is_eof(c->pkt.p, c->pkt.n) || (c->pkt.n && c->pkt.p[0] == 0xFF)) {
        int rc = 0;
        r->ended = 1;
        c->open = NULL;
        if (c->pkt.p[0] == 0xFF) {
            rc = server_err(c);
        } else {
            mw_ok ok;
            mw_parse_ok(c->pkt.p, c->pkt.n, &ok);
            c->status = ok.status;
            c->pending = (ok.status & SERVER_MORE_RESULTS_EXISTS) != 0;
        }
        return rc;
    }
    rd.p = c->pkt.p;
    rd.n = c->pkt.n;
    rd.bad = 0;
    r->cells.n = 0;
    for (i = 0; i < r->ncols; i++) {
        size_t n;
        const uint8_t *s = rd_lenenc_str(&rd, &n);
        if (!s && !rd.bad) {
            r->off[i] = NOT_NULL;
            r->len[i] = 0;
            continue;
        }
        r->off[i] = r->cells.n;
        r->len[i] = n;
        buf_put(&r->cells, s, n);
        buf_u8(&r->cells, 0);
    }
    if (rd.bad || r->cells.oom) {
        r->ended = 1;
        c->open = NULL;
        return lose(c, r->cells.oom ? "out of memory" : "unreadable row");
    }
    r->have_row = 1;
    return 1;
}

const char *mw_text(const mw_result *r, int col)
{
    if (!r->have_row || col < 0 || col >= r->ncols || r->off[col] == NOT_NULL)
        return NULL;
    return (const char *)r->cells.p + r->off[col];
}

size_t mw_len(const mw_result *r, int col)
{
    return r->have_row && col >= 0 && col < r->ncols ? r->len[col] : 0;
}

unsigned long long mw_rows_affected(const mw_result *r) { return r->affected; }
unsigned long long mw_insert_id(const mw_result *r) { return r->insert_id; }

void mw_free(mw_result *r)
{
    mw_conn *c;
    if (!r)
        return;
    c = r->c;
    /* The protocol has no way to drop a result: its rows must be read. */
    while (!r->ended && !c->lost && mw_next(r) > 0)
        ;
    result_free(r);
    drain(c);
}

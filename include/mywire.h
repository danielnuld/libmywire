/* libmywire: a native client for the MySQL and MariaDB protocol.
 *
 * Every function that can fail returns a negative value (or NULL) and leaves
 * a UTF-8 message in mw_error(). Strings are UTF-8 (utf8mb4) both ways. */
#ifndef MYWIRE_H
#define MYWIRE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mw_conn mw_conn;
typedef struct mw_result mw_result;

typedef enum {
    MW_TLS_OFF = 0,     /* plain TCP */
    MW_TLS_PREFER,      /* encrypted if the server offers it, unchecked */
    MW_TLS_REQUIRE,     /* encrypted, the server's certificate not checked */
    MW_TLS_VERIFY_CA,   /* encrypted, certificate signed by a trusted CA */
    MW_TLS_VERIFY_FULL, /* and issued for the host name or IP connected to */
} mw_tls_mode;

typedef struct {
    const char *host;
    int port;             /* 0 = 3306 */
    const char *user;
    const char *password; /* NULL = none */
    const char *database; /* NULL = none selected */
    mw_tls_mode tls;
    const char *ca_file;   /* PEM of the CAs to trust; NULL = OpenSSL's default
                            * paths (Windows and iOS have none: pass a file) */
    const char *cert_file; /* client certificate and key, PEM; optional */
    const char *key_file;
    int connect_timeout_ms; /* for each wait while logging in; 0 = 30000.
                             * Queries run without a timeout. */
} mw_options; /* zero it before filling it in */

/* Connect and log in with mysql_native_password or caching_sha2_password.
 * Without TLS, caching_sha2_password's first login encrypts the password
 * with the server's RSA key, fetched unauthenticated on the same connection.
 * Returns NULL and fills err (if given) on failure. */
mw_conn *mw_connect(const mw_options *o, char *err, int errlen);
void mw_close(mw_conn *c);

const char *mw_error(const mw_conn *c);
/* Server error number and SQLSTATE of the last failure (0 and "00000" if
 * it was not a server error). */
unsigned mw_errno(const mw_conn *c);
const char *mw_sqlstate(const mw_conn *c);

/* 1 once the connection is unusable (network failure, server hang-up or an
 * unreadable reply); every later call fails fast. An SQL error is not a lost
 * connection. */
int mw_conn_lost(const mw_conn *c);

unsigned long mw_thread_id(const mw_conn *c);
const char *mw_server_version(const mw_conn *c);
/* The TLS cipher in use, or NULL on a plain connection. */
const char *mw_tls_cipher(const mw_conn *c);

/* Stop the statement running on c, from any thread: it opens a second
 * connection with the same options and sends KILL QUERY. The statement fails
 * with error 1317 and c stays usable. Keep c alive until this returns. */
int mw_cancel(mw_conn *c);

/* Run one statement. Always yields a result: with columns to fetch row by
 * row as they arrive, or with none and mw_rows_affected(). A connection
 * holds one result at a time: fetch it to the end or mw_free it before the
 * next mw_query. Of a CALL that returns several results, the first one with
 * columns is given and the rest are skipped. */
int mw_query(mw_conn *c, const char *sql, size_t len, mw_result **out);

typedef struct {
    const char *name;
    unsigned type;     /* the protocol's column type, e.g. 3 = LONG, 253 = VAR_STRING */
    unsigned flags;    /* e.g. 1 = NOT NULL, 128 = BINARY */
    unsigned charset;  /* collation id; 63 = binary */
    unsigned long length;
    unsigned decimals;
} mw_column;

int mw_col_count(const mw_result *r);
const mw_column *mw_col(const mw_result *r, int col);

/* 1 = a row is ready, 0 = no more rows, <0 = error. */
int mw_next(mw_result *r);
/* A cell of the current row as text (BIT and binary columns raw), with a NUL
 * after it; NULL for SQL NULL. Valid until the next mw_next or mw_free. */
const char *mw_text(const mw_result *r, int col);
size_t mw_len(const mw_result *r, int col);
unsigned long long mw_rows_affected(const mw_result *r);
unsigned long long mw_insert_id(const mw_result *r);
void mw_free(mw_result *r);

/* Escape len bytes for use between quotes, following the server's
 * NO_BACKSLASH_ESCAPES mode. to needs room for 2*len+1. */
size_t mw_escape(const mw_conn *c, char *to, const char *from, size_t len);

#ifdef __cplusplus
}
#endif

#endif

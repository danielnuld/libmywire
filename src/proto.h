/* The MySQL/MariaDB client/server protocol's pure parts: byte buffers, the
 * integer and string encodings, the packets the client parses, and the
 * password scrambles. No sockets here, so every function is unit tested.
 *
 * Written from the public protocol documentation ("Client/Server Protocol" in
 * the MySQL source docs and "Clients & Connectors > Client/Server Protocol"
 * in the MariaDB knowledge base), never from a client library's code. */
#ifndef MW_PROTO_H
#define MW_PROTO_H

#include <stddef.h>
#include <stdint.h>

/* Capability flags. */
enum {
    CLIENT_LONG_PASSWORD = 0x1,
    CLIENT_LONG_FLAG = 0x4,
    CLIENT_CONNECT_WITH_DB = 0x8,
    CLIENT_PROTOCOL_41 = 0x200,
    CLIENT_SSL = 0x800,
    CLIENT_TRANSACTIONS = 0x2000,
    CLIENT_SECURE_CONNECTION = 0x8000,
    CLIENT_MULTI_RESULTS = 0x20000,
    CLIENT_PLUGIN_AUTH = 0x80000,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x200000,
};

/* Server status flags. */
enum {
    SERVER_MORE_RESULTS_EXISTS = 0x8,
    SERVER_NO_BACKSLASH_ESCAPES = 0x200,
};

#define MW_CHARSET_UTF8MB4 45 /* utf8mb4_general_ci: on MySQL 5.5.3+ and MariaDB */
#define MW_MAX_PACKET 0x01000000u

typedef struct {
    uint8_t *p;
    size_t n, cap;
    int oom;
} mw_buf;

void mw_buf_put(mw_buf *b, const void *p, size_t n);
void mw_buf_u8(mw_buf *b, unsigned v);
void mw_buf_le32(mw_buf *b, uint32_t v);
void mw_buf_lenenc(mw_buf *b, uint64_t v);
void mw_buf_free(mw_buf *b);

/* A read cursor. Reading past the end sets bad and yields zeros. */
typedef struct {
    const uint8_t *p;
    size_t n;
    int bad;
} mw_rd;

unsigned mw_rd_u8(mw_rd *r);
unsigned mw_rd_le16(mw_rd *r);
uint32_t mw_rd_le32(mw_rd *r);
/* A length-encoded integer; *is_null (if given) = 1 for the 0xFB marker. */
uint64_t mw_rd_lenenc(mw_rd *r, int *is_null);
/* n bytes, or NULL (and bad) if fewer remain. */
const uint8_t *mw_rd_bytes(mw_rd *r, size_t n);
/* A length-encoded string; returns NULL for the NULL marker. */
const uint8_t *mw_rd_lenenc_str(mw_rd *r, size_t *len);
/* A NUL-terminated string into out (truncated to cap-1); 0 if unterminated. */
int mw_rd_cstr(mw_rd *r, char *out, size_t cap);

typedef struct {
    unsigned protocol;
    char version[64];
    uint32_t thread_id;
    uint32_t caps;
    unsigned charset;
    unsigned status;
    uint8_t nonce[20];
    char plugin[64]; /* empty if the server did not name one */
} mw_handshake;

/* Protocol::HandshakeV10. -1 if malformed or not version 10. */
int mw_parse_handshake(const uint8_t *p, size_t n, mw_handshake *h);

typedef struct {
    uint64_t affected, insert_id;
    unsigned status, warnings;
} mw_ok;

/* An OK packet (0x00 header) or an EOF packet (0xFE, fewer than 9 bytes). */
int mw_parse_ok(const uint8_t *p, size_t n, mw_ok *ok);
int mw_is_eof(const uint8_t *p, size_t n);

typedef struct {
    unsigned code;
    char sqlstate[6];
    char message[400];
} mw_err;

int mw_parse_err(const uint8_t *p, size_t n, mw_err *e);

typedef struct {
    char name[256];
    uint32_t length;
    unsigned type, flags, charset, decimals;
} mw_coldef;

/* Protocol::ColumnDefinition41. */
int mw_parse_coldef(const uint8_t *p, size_t n, mw_coldef *c);

/* mysql_native_password: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw))). */
void mw_scramble_native(const char *password, const uint8_t nonce[20], uint8_t out[20]);
/* caching_sha2_password: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + nonce). */
void mw_scramble_sha2(const char *password, const uint8_t nonce[20], uint8_t out[32]);

/* Escape len bytes of from into to (room for 2*len+1) for use inside a
 * quoted literal; returns the length written, NUL not counted. With
 * no_backslash (the server's NO_BACKSLASH_ESCAPES mode) only ' is doubled. */
size_t mw_escape_str(char *to, const char *from, size_t len, int no_backslash);

#endif

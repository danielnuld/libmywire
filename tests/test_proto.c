/* Unit tests of the protocol's pure parts: no server needed. */
#include "proto.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void hex(const uint8_t *p, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", p[i]);
}

static void test_lenenc(void)
{
    static const uint64_t v[] = {0, 250, 251, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000, 1ull << 40};
    static const size_t size[] = {1, 1, 3, 3, 4, 4, 9, 9};
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        mw_buf b = {0};
        mw_rd r;
        int is_null;
        mw_buf_lenenc(&b, v[i]);
        CHECK(b.n == size[i]);
        r.p = b.p;
        r.n = b.n;
        r.bad = 0;
        CHECK(mw_rd_lenenc(&r, &is_null) == v[i]);
        CHECK(!is_null && !r.bad && r.n == 0);
        mw_buf_free(&b);
    }
    {
        static const uint8_t null_marker[] = {0xFB}, truncated[] = {0xFC, 0x01};
        mw_rd r = {null_marker, 1, 0};
        size_t len = 99;
        CHECK(mw_rd_lenenc_str(&r, &len) == NULL && !r.bad && len == 0);
        r.p = truncated;
        r.n = 2;
        mw_rd_lenenc(&r, NULL);
        CHECK(r.bad);
    }
    {
        /* A string longer than what is left is refused, not over-read. */
        static const uint8_t lying[] = {0x05, 'a', 'b'};
        mw_rd r = {lying, 3, 0};
        size_t len;
        CHECK(mw_rd_lenenc_str(&r, &len) == NULL && r.bad);
    }
}

/* A HandshakeV10 as MySQL 8.4 sends it. */
static size_t mysql_greeting(uint8_t *p)
{
    size_t n = 0;
    p[n++] = 10;
    memcpy(p + n, "8.4.2", 6);
    n += 6;
    p[n++] = 0x2A; p[n++] = 0; p[n++] = 0; p[n++] = 0; /* thread 42 */
    memcpy(p + n, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    n += 8;
    p[n++] = 0;
    p[n++] = 0xFF; p[n++] = 0xFF; /* caps low: PROTOCOL_41, SSL, SECURE... */
    p[n++] = 255;                /* utf8mb4_0900_ai_ci */
    p[n++] = 0x02; p[n++] = 0x00;
    p[n++] = 0xFF; p[n++] = 0xDF; /* caps high: PLUGIN_AUTH and more */
    p[n++] = 21;
    memset(p + n, 0, 10);
    n += 10;
    memcpy(p + n, "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x00", 13);
    n += 13;
    memcpy(p + n, "caching_sha2_password", 22);
    return n + 22;
}

static void test_handshake(void)
{
    uint8_t p[128];
    size_t n = mysql_greeting(p);
    mw_handshake h;
    int i, ok = 1;
    CHECK(mw_parse_handshake(p, n, &h) == 0);
    CHECK(!strcmp(h.version, "8.4.2"));
    CHECK(h.thread_id == 42);
    CHECK(h.caps & CLIENT_PROTOCOL_41);
    CHECK(h.caps & CLIENT_PLUGIN_AUTH);
    CHECK(h.status == 2);
    for (i = 0; i < 20; i++)
        ok &= h.nonce[i] == i + 1;
    CHECK(ok);
    CHECK(!strcmp(h.plugin, "caching_sha2_password"));

    /* Plugin name without its NUL (the packet just ends). */
    CHECK(mw_parse_handshake(p, n - 1, &h) == 0 && !strcmp(h.plugin, "caching_sha2_password"));
    /* Cut inside the nonce: refused. */
    CHECK(mw_parse_handshake(p, 40, &h) < 0);
    /* Not protocol 10. */
    p[0] = 9;
    CHECK(mw_parse_handshake(p, n, &h) < 0);
}

static void test_ok_eof_err(void)
{
    static const uint8_t ok[] = {0x00, 0xFC, 0x10, 0x27, 0x07, 0x02, 0x00, 0x01, 0x00};
    static const uint8_t eof[] = {0xFE, 0x03, 0x00, 0x0A, 0x00};
    static const uint8_t err[] = {0xFF, 0x7A, 0x04, '#', '4', '2', 'S', '0', '2',
                                  'n', 'o', ' ', 't', 'a', 'b', 'l', 'e'};
    static const uint8_t early[] = {0xFF, 0x6A, 0x04, 'H', 'o', 's', 't'};
    mw_ok o;
    mw_err e;
    CHECK(mw_parse_ok(ok, sizeof ok, &o) == 0);
    CHECK(o.affected == 10000 && o.insert_id == 7 && o.status == 2 && o.warnings == 1);
    CHECK(mw_is_eof(eof, sizeof eof) && !mw_is_eof(ok, sizeof ok));
    CHECK(mw_parse_ok(eof, sizeof eof, &o) == 0);
    CHECK(o.warnings == 3 && o.status == 10);
    CHECK(mw_parse_err(err, sizeof err, &e) == 0);
    CHECK(e.code == 1146 && !strcmp(e.sqlstate, "42S02") && !strcmp(e.message, "no table"));
    CHECK(mw_parse_err(early, sizeof early, &e) == 0);
    CHECK(e.code == 1130 && !strcmp(e.sqlstate, "HY000") && !strcmp(e.message, "Host"));
    /* A row beginning with an 8-byte length is not an EOF. */
    {
        uint8_t row[12] = {0xFE};
        CHECK(!mw_is_eof(row, sizeof row));
    }
}

static void test_coldef(void)
{
    mw_buf b = {0};
    mw_coldef d;
    static const char *const s[] = {"def", "testdb", "t", "t", "nombre", "nombre"};
    size_t i;
    for (i = 0; i < 6; i++) {
        mw_buf_lenenc(&b, strlen(s[i]));
        mw_buf_put(&b, s[i], strlen(s[i]));
    }
    mw_buf_lenenc(&b, 0x0c);
    mw_buf_put(&b, "\x2d\x00", 2);          /* utf8mb4_general_ci */
    mw_buf_le32(&b, 400);
    mw_buf_u8(&b, 253);                     /* VAR_STRING */
    mw_buf_put(&b, "\x01\x00", 2);          /* NOT NULL */
    mw_buf_u8(&b, 0);
    mw_buf_put(&b, "\x00\x00", 2);
    CHECK(mw_parse_coldef(b.p, b.n, &d) == 0);
    CHECK(!strcmp(d.name, "nombre") && d.charset == 45 && d.length == 400);
    CHECK(d.type == 253 && d.flags == 1 && d.decimals == 0);
    CHECK(mw_parse_coldef(b.p, b.n - 8, &d) < 0);
    mw_buf_free(&b);
}

static void test_scrambles(void)
{
    uint8_t nonce[20], out[32];
    char h[65];
    int i;
    for (i = 0; i < 20; i++)
        nonce[i] = (uint8_t)(i + 1);
    /* Expected values computed independently with Python's hashlib. */
    mw_scramble_native("secret", nonce, out);
    hex(out, 20, h);
    CHECK(!strcmp(h, "b32bb3a583e1340c0a1108d58b1be49781ad8c2f"));
    mw_scramble_sha2("secret", nonce, out);
    hex(out, 32, h);
    CHECK(!strcmp(h, "746ebe205d56a0707acb3e796e834e0dd7b1d61743b26bd5202c7a623230c7c9"));
}

static void test_escape(void)
{
    char out[64];
    static const char in[] = "a'b\"c\\d\ne\rf\032g\0h";
    size_t n = mw_escape_str(out, in, sizeof in - 1, 0);
    CHECK(n == 22 && !memcmp(out, "a\\'b\\\"c\\\\d\\ne\\rf\\Zg\\0h", 22));
    n = mw_escape_str(out, "it's \\ ok", 9, 1);
    CHECK(n == 10 && !strcmp(out, "it''s \\ ok"));
    CHECK(mw_escape_str(out, "ñandú", strlen("ñandú"), 0) == strlen("ñandú"));
}

int main(void)
{
    test_lenenc();
    test_handshake();
    test_ok_eof_err();
    test_coldef();
    test_scrambles();
    test_escape();
    if (failures)
        fprintf(stderr, "%d failure(s)\n", failures);
    else
        printf("proto: all passed\n");
    return failures != 0;
}

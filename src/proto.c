#include "proto.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

/* ---- buffers -------------------------------------------------------- */

void buf_put(mw_buf *b, const void *p, size_t n)
{
    if (b->oom || !n)
        return;
    if (b->n + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        uint8_t *q;
        while (cap < b->n + n)
            cap *= 2;
        q = (uint8_t *)realloc(b->p, cap);
        if (!q) {
            b->oom = 1;
            return;
        }
        b->p = q;
        b->cap = cap;
    }
    memcpy(b->p + b->n, p, n);
    b->n += n;
}

void buf_u8(mw_buf *b, unsigned v)
{
    uint8_t c = (uint8_t)v;
    buf_put(b, &c, 1);
}

void buf_le32(mw_buf *b, uint32_t v)
{
    uint8_t c[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    buf_put(b, c, 4);
}

void buf_lenenc(mw_buf *b, uint64_t v)
{
    uint8_t c[9];
    int i, k;
    if (v < 251) {
        buf_u8(b, (unsigned)v);
        return;
    }
    if (v < 0x10000) {
        c[0] = 0xFC;
        k = 2;
    } else if (v < 0x1000000) {
        c[0] = 0xFD;
        k = 3;
    } else {
        c[0] = 0xFE;
        k = 8;
    }
    for (i = 0; i < k; i++)
        c[1 + i] = (uint8_t)(v >> (8 * i));
    buf_put(b, c, (size_t)k + 1);
}

void buf_free(mw_buf *b)
{
    free(b->p);
    memset(b, 0, sizeof *b);
}

/* ---- reading -------------------------------------------------------- */

const uint8_t *rd_bytes(mw_rd *r, size_t n)
{
    const uint8_t *p;
    if (r->bad || r->n < n) {
        r->bad = 1;
        return NULL;
    }
    p = r->p;
    r->p += n;
    r->n -= n;
    return p;
}

static uint64_t rd_le(mw_rd *r, int k)
{
    const uint8_t *p = rd_bytes(r, (size_t)k);
    uint64_t v = 0;
    int i;
    if (!p)
        return 0;
    for (i = 0; i < k; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

unsigned rd_u8(mw_rd *r) { return (unsigned)rd_le(r, 1); }
unsigned rd_le16(mw_rd *r) { return (unsigned)rd_le(r, 2); }
uint32_t rd_le32(mw_rd *r) { return (uint32_t)rd_le(r, 4); }

uint64_t rd_lenenc(mw_rd *r, int *is_null)
{
    unsigned c = rd_u8(r);
    if (is_null)
        *is_null = c == 0xFB;
    switch (c) {
    case 0xFB: return 0;
    case 0xFC: return rd_le(r, 2);
    case 0xFD: return rd_le(r, 3);
    case 0xFE: return rd_le(r, 8);
    case 0xFF: r->bad = 1; return 0; /* never a length */
    default: return c;
    }
}

const uint8_t *rd_lenenc_str(mw_rd *r, size_t *len)
{
    int is_null;
    uint64_t n = rd_lenenc(r, &is_null);
    *len = 0;
    if (is_null || r->bad)
        return NULL;
    if (n > r->n) {
        r->bad = 1;
        return NULL;
    }
    *len = (size_t)n;
    return rd_bytes(r, (size_t)n);
}

int rd_cstr(mw_rd *r, char *out, size_t cap)
{
    const uint8_t *z = r->bad ? NULL : (const uint8_t *)memchr(r->p, 0, r->n);
    size_t n, k;
    if (!z) {
        r->bad = 1;
        return 0;
    }
    n = (size_t)(z - r->p);
    k = n < cap - 1 ? n : cap - 1;
    memcpy(out, r->p, k);
    out[k] = 0;
    rd_bytes(r, n + 1);
    return 1;
}

static void copy_str(char *out, size_t cap, const uint8_t *p, size_t n)
{
    size_t k = n < cap - 1 ? n : cap - 1;
    if (p)
        memcpy(out, p, k);
    else
        k = 0;
    out[k] = 0;
}

/* ---- packets -------------------------------------------------------- */

int mw_parse_handshake(const uint8_t *p, size_t n, mw_handshake *h)
{
    mw_rd r = {p, n, 0};
    const uint8_t *part1;
    memset(h, 0, sizeof *h);
    h->protocol = rd_u8(&r);
    if (h->protocol != 10 || !rd_cstr(&r, h->version, sizeof h->version))
        return -1;
    h->thread_id = rd_le32(&r);
    part1 = rd_bytes(&r, 8);
    rd_u8(&r); /* filler */
    h->caps = rd_le16(&r);
    if (r.bad || !part1)
        return -1;
    memcpy(h->nonce, part1, 8);
    if (!r.n)
        return 0; /* a pre-4.1 server: the caller refuses it for lacking PROTOCOL_41 */
    {
        unsigned authlen;
        h->charset = rd_u8(&r);
        h->status = rd_le16(&r);
        h->caps |= (uint32_t)rd_le16(&r) << 16;
        authlen = rd_u8(&r);
        rd_bytes(&r, 10); /* reserved (MariaDB keeps extended capabilities here) */
        if (h->caps & CLIENT_SECURE_CONNECTION) {
            size_t k = authlen > 8 + 13 ? authlen - 8 : 13;
            const uint8_t *part2 = rd_bytes(&r, k);
            if (!part2)
                return -1;
            memcpy(h->nonce + 8, part2, 12);
        }
        if (h->caps & CLIENT_PLUGIN_AUTH) {
            /* Usually NUL-terminated, but some servers end the packet instead. */
            const uint8_t *z = (const uint8_t *)memchr(r.p, 0, r.n);
            copy_str(h->plugin, sizeof h->plugin, r.p, z ? (size_t)(z - r.p) : r.n);
        }
    }
    return r.bad ? -1 : 0;
}

int mw_is_eof(const uint8_t *p, size_t n) { return n > 0 && n < 9 && p[0] == 0xFE; }

int mw_parse_ok(const uint8_t *p, size_t n, mw_ok *ok)
{
    mw_rd r = {p, n, 0};
    memset(ok, 0, sizeof *ok);
    if (mw_is_eof(p, n)) {
        rd_u8(&r);
        ok->warnings = rd_le16(&r);
        ok->status = rd_le16(&r);
        return r.bad ? -1 : 0;
    }
    if (rd_u8(&r) != 0x00 && !(n && p[0] == 0xFE))
        return -1;
    ok->affected = rd_lenenc(&r, NULL);
    ok->insert_id = rd_lenenc(&r, NULL);
    ok->status = rd_le16(&r);
    ok->warnings = rd_le16(&r);
    return r.bad ? -1 : 0;
}

int mw_parse_err(const uint8_t *p, size_t n, mw_err *e)
{
    mw_rd r = {p, n, 0};
    memset(e, 0, sizeof *e);
    if (rd_u8(&r) != 0xFF)
        return -1;
    e->code = rd_le16(&r);
    if (r.bad)
        return -1;
    /* Errors sent before the handshake completes carry no SQLSTATE. */
    if (r.n >= 6 && r.p[0] == '#') {
        copy_str(e->sqlstate, sizeof e->sqlstate, r.p + 1, 5);
        rd_bytes(&r, 6);
    } else {
        memcpy(e->sqlstate, "HY000", 6);
    }
    copy_str(e->message, sizeof e->message, r.p, r.n);
    return 0;
}

int mw_parse_coldef(const uint8_t *p, size_t n, mw_coldef *c)
{
    mw_rd r = {p, n, 0};
    size_t len;
    const uint8_t *name;
    int i;
    memset(c, 0, sizeof *c);
    for (i = 0; i < 4; i++) /* catalog, schema, table, org_table */
        rd_lenenc_str(&r, &len);
    name = rd_lenenc_str(&r, &len);
    copy_str(c->name, sizeof c->name, name, len);
    rd_lenenc_str(&r, &len); /* org_name */
    rd_lenenc(&r, NULL);     /* length of the fixed fields, 0x0c */
    c->charset = rd_le16(&r);
    c->length = rd_le32(&r);
    c->type = rd_u8(&r);
    c->flags = rd_le16(&r);
    c->decimals = rd_u8(&r);
    return r.bad ? -1 : 0;
}

/* ---- scrambles ------------------------------------------------------ */

/* The digest of a followed by b (b may be empty). */
static void digest(const EVP_MD *md, const void *a, size_t an, const void *b, size_t bn,
                   uint8_t *out)
{
    EVP_MD_CTX *x = EVP_MD_CTX_new();
    EVP_DigestInit_ex(x, md, NULL);
    EVP_DigestUpdate(x, a, an);
    EVP_DigestUpdate(x, b, bn);
    EVP_DigestFinal_ex(x, out, NULL);
    EVP_MD_CTX_free(x);
}

void mw_scramble_native(const char *password, const uint8_t nonce[20], uint8_t out[20])
{
    uint8_t h1[20], h2[20], h3[20];
    int i;
    digest(EVP_sha1(), password, strlen(password), NULL, 0, h1);
    digest(EVP_sha1(), h1, 20, NULL, 0, h2);
    digest(EVP_sha1(), nonce, 20, h2, 20, h3);
    for (i = 0; i < 20; i++)
        out[i] = h1[i] ^ h3[i];
}

void mw_scramble_sha2(const char *password, const uint8_t nonce[20], uint8_t out[32])
{
    uint8_t h1[32], h2[32], h3[32];
    int i;
    digest(EVP_sha256(), password, strlen(password), NULL, 0, h1);
    digest(EVP_sha256(), h1, 32, NULL, 0, h2);
    digest(EVP_sha256(), h2, 32, nonce, 20, h3);
    for (i = 0; i < 32; i++)
        out[i] = h1[i] ^ h3[i];
}

/* ---- escaping ------------------------------------------------------- */

size_t mw_escape_str(char *to, const char *from, size_t len, int no_backslash)
{
    char *o = to;
    size_t i;
    for (i = 0; i < len; i++) {
        char c = from[i], e = 0;
        if (no_backslash) {
            if (c == '\'')
                *o++ = '\'';
            *o++ = c;
            continue;
        }
        switch (c) {
        case 0: e = '0'; break;
        case '\n': e = 'n'; break;
        case '\r': e = 'r'; break;
        case '\\': e = '\\'; break;
        case '\'': e = '\''; break;
        case '"': e = '"'; break;
        case '\032': e = 'Z'; break;
        default: break;
        }
        if (e) {
            *o++ = '\\';
            *o++ = e;
        } else {
            *o++ = c;
        }
    }
    *o = 0;
    return (size_t)(o - to);
}

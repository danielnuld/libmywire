/* Live tests against a MySQL or MariaDB server. Skipped (exit 77) unless
 * MW_TEST_HOST is set. Also reads:
 *   MW_TEST_PORT, MW_TEST_USER, MW_TEST_PASSWORD, MW_TEST_DB
 *       a user that may create tables in the database and FLUSH PRIVILEGES;
 *   MW_TEST_SHA2_USER, MW_TEST_SHA2_PASSWORD (optional)
 *       a caching_sha2_password user, to force its full authentication both
 *       over TLS and with the server's RSA key;
 *   MW_TEST_TLS=1 (optional) the server speaks TLS;
 *   MW_TEST_CA (optional) the CA that signed the server's certificate, whose
 *       name is NOT the host tested (verify-ca passes, verify-full fails). */
/* nanosleep and pthreads are hidden by a strict -std=c11; ask for them. */
#if !defined(_WIN32)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#    define _DARWIN_C_SOURCE
#  endif
#endif

#include "mywire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
#include <pthread.h>
static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static int cancel_rc = 1;

#ifdef _WIN32
static DWORD WINAPI canceller(LPVOID arg)
#else
static void *canceller(void *arg)
#endif
{
    sleep_ms(1000);
    cancel_rc = mw_cancel((mw_conn *)arg);
    return 0;
}

static void start_canceller(mw_conn *c)
{
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, canceller, c, 0, NULL);
    if (h)
        CloseHandle(h);
#else
    pthread_t t;
    if (pthread_create(&t, NULL, canceller, c) == 0)
        pthread_detach(t);
#endif
}

static mw_options base;

static mw_conn *connect_as(const char *user, const char *password, mw_tls_mode tls,
                           const char *ca, char *err)
{
    mw_options o = base;
    o.user = user;
    o.password = password;
    o.tls = tls;
    o.ca_file = ca;
    return mw_connect(&o, err, 512);
}

static int q(mw_conn *c, const char *sql, mw_result **r)
{
    return mw_query(c, sql, strlen(sql), r);
}

/* Run sql to completion; -1 on error, its message printed. */
static int run(mw_conn *c, const char *sql)
{
    mw_result *r;
    if (mw_query(c, sql, strlen(sql), &r) < 0) {
        fprintf(stderr, "  %s: %s\n", sql, mw_error(c));
        return -1;
    }
    while (mw_next(r) > 0)
        ;
    mw_free(r);
    return 0;
}

/* The first cell of the first row of sql, into out. */
static int scalar(mw_conn *c, const char *sql, char *out, size_t cap)
{
    mw_result *r;
    int rc = -1;
    out[0] = 0;
    if (mw_query(c, sql, strlen(sql), &r) < 0) {
        fprintf(stderr, "  %s: %s\n", sql, mw_error(c));
        return -1;
    }
    if (mw_next(r) > 0) {
        const char *t = mw_text(r, 0);
        snprintf(out, cap, "%s", t ? t : "(null)");
        rc = 0;
    }
    mw_free(r);
    return rc;
}

static const char TEN[] = "(SELECT 0 n UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 "
                          "UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 "
                          "UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)";

static void test_basics(mw_conn *c)
{
    char v[256], sql[1024];
    mw_result *r;
    CHECK(scalar(c, "SELECT 1 + 1", v, sizeof v) == 0 && !strcmp(v, "2"));
    CHECK(scalar(c, "SELECT @@character_set_client", v, sizeof v) == 0 && !strcmp(v, "utf8mb4"));
    printf("  server %s, thread %lu\n", mw_server_version(c), mw_thread_id(c));

    run(c, "DROP TABLE IF EXISTS mw_live");
    CHECK(run(c, "CREATE TABLE mw_live (id INT PRIMARY KEY, name VARCHAR(40), price DECIMAL(10,2), "
                 "born DATE, at DATETIME(3), flags BIT(8), blob_ BLOB, note TEXT, f DOUBLE)") == 0);

    /* UTF-8 both ways, an escaped literal, binary, NULL and the types. */
    {
        static const char name[] = "Peña's \"Ñandú\" \\ 🐘";
        char esc[128];
        mw_escape(c, esc, name, strlen(name));
        snprintf(sql, sizeof sql,
                 "INSERT INTO mw_live VALUES (1, '%s', 1234.50, '2026-09-25', "
                 "'2026-09-25 10:11:12.345', b'10100101', x'00FF0041', NULL, 0.5), "
                 "(2, NULL, NULL, NULL, NULL, NULL, NULL, 'x', NULL)",
                 esc);
        CHECK(mw_query(c, sql, strlen(sql), &r) == 0);
        if (r) {
            CHECK(mw_col_count(r) == 0 && mw_rows_affected(r) == 2);
            mw_free(r);
        }
        CHECK(q(c, "SELECT * FROM mw_live ORDER BY id", &r) == 0);
        if (r) {
            CHECK(mw_col_count(r) == 9);
            CHECK(!strcmp(mw_col(r, 1)->name, "name") && mw_col(r, 1)->type == 253);
            CHECK(mw_col(r, 0)->type == 3 && (mw_col(r, 0)->flags & 1));
            CHECK(mw_col(r, 5)->type == 16);          /* BIT */
            CHECK(mw_col(r, 6)->charset == 63);       /* binary */
            CHECK(mw_next(r) == 1);
            CHECK(!strcmp(mw_text(r, 1), name));
            CHECK(!strcmp(mw_text(r, 2), "1234.50"));
            CHECK(!strcmp(mw_text(r, 3), "2026-09-25"));
            CHECK(!strcmp(mw_text(r, 4), "2026-09-25 10:11:12.345"));
            CHECK(mw_len(r, 5) == 1 && (unsigned char)mw_text(r, 5)[0] == 0xA5);
            CHECK(mw_len(r, 6) == 4 && !memcmp(mw_text(r, 6), "\0\xff\0A", 4));
            CHECK(mw_text(r, 7) == NULL);
            CHECK(!strcmp(mw_text(r, 8), "0.5"));
            CHECK(mw_next(r) == 1);
            CHECK(mw_text(r, 1) == NULL && mw_text(r, 2) == NULL && !strcmp(mw_text(r, 7), "x"));
            CHECK(mw_next(r) == 0);
            mw_free(r);
        }
    }

    /* Affected rows: matched, not found. */
    CHECK(q(c, "UPDATE mw_live SET price = 1 WHERE id IN (1, 2)", &r) == 0);
    if (r) {
        CHECK(mw_rows_affected(r) == 2);
        mw_free(r);
    }

    /* A server error: its number, SQLSTATE and message; the connection lives. */
    CHECK(q(c, "SELECT * FROM mw_missing", &r) < 0 && r == NULL);
    CHECK(mw_errno(c) == 1146 && !strcmp(mw_sqlstate(c), "42S02"));
    CHECK(strstr(mw_error(c), "mw_missing") != NULL && !mw_conn_lost(c));
    CHECK(scalar(c, "SELECT 3", v, sizeof v) == 0 && !strcmp(v, "3"));

    /* Transactions. */
    CHECK(run(c, "START TRANSACTION") == 0);
    CHECK(run(c, "DELETE FROM mw_live") == 0);
    CHECK(run(c, "ROLLBACK") == 0);
    CHECK(scalar(c, "SELECT COUNT(*) FROM mw_live", v, sizeof v) == 0 && !strcmp(v, "2"));
    run(c, "DROP TABLE mw_live");
}

static void test_streaming(mw_conn *c)
{
    char sql[1024], v[32];
    mw_result *r, *r2;
    long n = 0, sum = 0;
    /* 10 000 rows, read one by one. */
    snprintf(sql, sizeof sql, "SELECT a.n*1000+b.n*100+c.n*10+d.n FROM %s a, %s b, %s c, %s d",
             TEN, TEN, TEN, TEN);
    CHECK(mw_query(c, sql, strlen(sql), &r) == 0);
    if (r) {
        int rc;
        while ((rc = mw_next(r)) > 0) {
            n++;
            sum += atol(mw_text(r, 0));
        }
        CHECK(rc == 0 && n == 10000 && sum == 49995000L);
        mw_free(r);
    }
    /* Only one result at a time: the second query is refused, not garbled. */
    CHECK(mw_query(c, sql, strlen(sql), &r) == 0);
    if (r) {
        CHECK(mw_next(r) == 1);
        CHECK(q(c, "SELECT 1", &r2) < 0 && r2 == NULL);
        CHECK(strstr(mw_error(c), "still open") != NULL);
        mw_free(r); /* freed half read: the rest is skipped */
    }
    CHECK(scalar(c, "SELECT 4", v, sizeof v) == 0 && !strcmp(v, "4"));
}

static void test_call(mw_conn *c)
{
    char v[32];
    run(c, "DROP PROCEDURE IF EXISTS mw_proc");
    CHECK(run(c, "CREATE PROCEDURE mw_proc() BEGIN SELECT 'first'; SELECT 'second'; END") == 0);
    /* The first result; the second and the final OK are skipped. */
    CHECK(scalar(c, "CALL mw_proc()", v, sizeof v) == 0 && !strcmp(v, "first"));
    CHECK(scalar(c, "SELECT 5", v, sizeof v) == 0 && !strcmp(v, "5"));
    run(c, "DROP PROCEDURE mw_proc");
}

static void test_cancel(mw_conn *c)
{
    /* Slow on any server: a cross join of the catalog, three times over. */
    static const char slow[] = "SELECT COUNT(*) FROM information_schema.columns a, "
                               "information_schema.columns b, information_schema.columns c";
    mw_result *r = NULL;
    char v[32];
    time_t t0 = time(NULL);
    int rc;
    start_canceller(c);
    rc = mw_query(c, slow, strlen(slow), &r);
    if (rc == 0) { /* the error may come with the rows */
        rc = mw_next(r) < 0 ? -1 : 0;
        mw_free(r);
    }
    CHECK(rc < 0 && mw_errno(c) == 1317);
    CHECK(time(NULL) - t0 < 10);
    sleep_ms(300); /* the canceller thread is done with c */
    CHECK(cancel_rc == 0);
    CHECK(!mw_conn_lost(c) && scalar(c, "SELECT 6", v, sizeof v) == 0 && !strcmp(v, "6"));
}

static void test_bad_password(void)
{
    char err[512];
    mw_conn *c = connect_as(base.user, "wrong password", MW_TLS_OFF, NULL, err);
    CHECK(c == NULL && strstr(err, "Access denied") != NULL);
    mw_close(c);
}

static void test_sha2(mw_conn *root, const char *user, const char *pw, int tls)
{
    char err[512];
    mw_conn *c;
    /* FLUSH PRIVILEGES empties caching_sha2_password's cache, so the next
     * login takes the full authentication. */
    CHECK(run(root, "FLUSH PRIVILEGES") == 0);
    c = connect_as(user, pw, MW_TLS_OFF, NULL, err);
    if (!c)
        fprintf(stderr, "  sha2 plain: %s\n", err);
    CHECK(c != NULL); /* RSA key exchange */
    mw_close(c);
    c = connect_as(user, pw, MW_TLS_OFF, NULL, err); /* the cached, fast path */
    CHECK(c != NULL);
    mw_close(c);
    if (tls) {
        CHECK(run(root, "FLUSH PRIVILEGES") == 0);
        c = connect_as(user, pw, MW_TLS_REQUIRE, NULL, err);
        if (!c)
            fprintf(stderr, "  sha2 TLS: %s\n", err);
        CHECK(c != NULL && mw_tls_cipher(c) != NULL);
        mw_close(c);
    }
    c = connect_as(user, "nope", MW_TLS_OFF, NULL, err);
    CHECK(c == NULL && strstr(err, "Access denied") != NULL);
    mw_close(c);
}

static void test_tls(const char *ca)
{
    char err[512], v[64];
    mw_conn *c = connect_as(base.user, base.password, MW_TLS_REQUIRE, NULL, err);
    if (!c)
        fprintf(stderr, "  TLS: %s\n", err);
    CHECK(c != NULL && mw_tls_cipher(c) != NULL);
    if (c) {
        CHECK(scalar(c, "SELECT 7", v, sizeof v) == 0 && !strcmp(v, "7"));
        mw_close(c);
    }
    if (!ca)
        return;
    c = connect_as(base.user, base.password, MW_TLS_VERIFY_CA, ca, err);
    if (!c)
        fprintf(stderr, "  verify-ca: %s\n", err);
    CHECK(c != NULL);
    mw_close(c);
    c = connect_as(base.user, base.password, MW_TLS_VERIFY_FULL, ca, err);
    CHECK(c == NULL && strstr(err, "certificate") != NULL);
    mw_close(c);
}

int main(void)
{
    const char *host = getenv("MW_TEST_HOST"), *port = getenv("MW_TEST_PORT");
    const char *sha2 = getenv("MW_TEST_SHA2_USER"), *tls = getenv("MW_TEST_TLS");
    char err[512];
    mw_conn *c;
    if (!host || !*host) {
        printf("MW_TEST_HOST not set: skipping\n");
        return 77;
    }
    base.host = host;
    base.port = port ? atoi(port) : 3306;
    base.user = getenv("MW_TEST_USER") ? getenv("MW_TEST_USER") : "root";
    base.password = getenv("MW_TEST_PASSWORD");
    base.database = getenv("MW_TEST_DB") ? getenv("MW_TEST_DB") : "test";
    c = mw_connect(&base, err, sizeof err);
    if (!c) {
        fprintf(stderr, "connect: %s\n", err);
        return 1;
    }
    test_basics(c);
    test_streaming(c);
    test_call(c);
    test_cancel(c);
    test_bad_password();
    if (sha2 && *sha2)
        test_sha2(c, sha2, getenv("MW_TEST_SHA2_PASSWORD"), tls && *tls == '1');
    if (tls && *tls == '1')
        test_tls(getenv("MW_TEST_CA"));
    mw_close(c);
    if (failures)
        fprintf(stderr, "%d failure(s)\n", failures);
    else
        printf("live: all passed\n");
    return failures != 0;
}

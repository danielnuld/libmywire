# libmywire

A small client for the MySQL and MariaDB client/server protocol, in C11, under
the Apache License 2.0. It exists so [Squaero](https://github.com/danielnuld/squaero)
can speak MySQL where the LGPL clients cannot go (the iPhone App Store).

It is written **only from the public protocol documentation** — the
[MySQL client/server protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html)
and the [MariaDB protocol pages](https://mariadb.com/kb/en/clientserver-protocol/) —
and never from the code of MariaDB Connector/C or libmysqlclient.

## What it does

- Logs in with `mysql_native_password` and `caching_sha2_password` (fast and full
  authentication: the password over TLS, or encrypted with the server's RSA key),
  following an authentication switch.
- TLS through OpenSSL: off, prefer, require, verify-ca and verify-full, with an
  optional client certificate.
- Text queries: result sets read **row by row** as they arrive, affected rows and
  insert id, server errors with their number and SQLSTATE.
- Cancels a running statement from another thread with `KILL QUERY` on a second
  connection; the first one stays usable.
- utf8mb4 both ways; escaping that follows `NO_BACKSLASH_ESCAPES`.

Not yet: prepared statements (binary protocol), `LOAD DATA LOCAL`, compression,
Unix sockets, `client_ed25519` and the other plugins.

```c
mw_options o = {0};
o.host = "127.0.0.1";
o.user = "root";
o.password = "secret";
o.database = "test";
o.tls = MW_TLS_PREFER;
char err[512];
mw_conn *c = mw_connect(&o, err, sizeof err);
const char *sql = "SELECT id, name FROM t";
mw_result *r;
if (c && mw_query(c, sql, strlen(sql), &r) == 0) {
    while (mw_next(r) > 0)
        printf("%s %s\n", mw_text(r, 0), mw_text(r, 1) ? mw_text(r, 1) : "NULL");
    mw_free(r);
}
mw_close(c);
```

A connection holds one result at a time; fetch it to the end or `mw_free` it
before the next query.

## Building and testing

Needs CMake and OpenSSL 1.1.1 or later.

```sh
cmake -S . -B build -DMW_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

`test_live` runs against a server when `MW_TEST_HOST` is set (see the comment at
the top of `tests/test_live.c` for the other variables); CI runs it against
MySQL 8.4 and MariaDB 11 under AddressSanitizer and UBSan.

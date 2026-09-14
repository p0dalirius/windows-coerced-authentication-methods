# MS-FAX - Remote call to FaxObs_SendDocument (opnum 5)

## Summary

+ **Protocol**: [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)

+ **Protocol UUID**: 6099fc12-3eff-11d0-abd0-00c04fd91a4e

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\SHAREDFAX`

+ **Function name**: [`FaxObs_SendDocument`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/21b87199-d4e7-472c-9190-90c6bb16d947)

+ **Function operation number**: `5`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\SHAREDFAX` and bind to the desired [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol (with uuid `6099fc12-3eff-11d0-abd0-00c04fd91a4e` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol.

**This call cannot be used to coerce an authentication.** The `FileName` parameter is documented as "the name of the file, **without path information**, of the fax document" and "**the server checks the server queue directory for this file**" ([MS-FAX] 3.1.4.2.7). The name is resolved inside the fax server's own queue directory, not opened as a client-supplied path, so it cannot be pointed at a remote UNC path. The IDL error conditions confirm this: `ERROR_INVALID_PARAMETER` is returned when "the length of the character string specified by the *FileName* parameter ... plus the length of the fax queue directory path name ... exceeds 253 characters", i.e. the server concatenates the name onto its local queue path. The intended way to place content on the server is to first call `FaxObs_GetQueueFileName` and then write the file over a separate protocol such as [MS-SMB] — the server never reaches out on the client's behalf.

## Function technical detail

```cpp
error_status_t FaxObs_SendDocument(
   [in] handle_t hBinding,
   [in, string, unique] LPCWSTR FileName,
   [in] const FAX_JOB_PARAMW* JobParams,
   [out] LPDWORD FaxJobId
 );
```

## References

+ Documentation of protocol [MS-FAX]: Fax Server and Client Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4

+ Documentation of function `FaxObs_SendDocument`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/21b87199-d4e7-472c-9190-90c6bb16d947
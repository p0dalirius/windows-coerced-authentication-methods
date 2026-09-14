# MS-FAX - Remote call to FaxObs_GetQueueFileName (opnum 6)

## Summary

+ **Protocol**: [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)

+ **Protocol UUID**: 6099fc12-3eff-11d0-abd0-00c04fd91a4e

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\SHAREDFAX`

+ **Function name**: [`FaxObs_GetQueueFileName`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/21d0c234-8dca-4f96-b7ea-2bdce029ee00)

+ **Function operation number**: `6`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\SHAREDFAX` and bind to the desired [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol (with uuid `6099fc12-3eff-11d0-abd0-00c04fd91a4e` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol.

**This call cannot be used to coerce an authentication.** It takes no client-supplied path at all. The only string parameter, `FileName`, is an `[in, out]` buffer that the **server writes**: the server generates a unique file name in its own queue directory and returns it to the client ([MS-FAX] 3.1.4.2.8). The client supplies only the buffer size. Because the client controls no path that the server resolves, there is nothing that can be directed at a listener.

## Function technical detail

```cpp
error_status_t FaxObs_GetQueueFileName(
   [in] handle_t hBinding,
   [in, out, unique, size_is(FileNameSize)] 
     LPWSTR FileName,
   [in] DWORD FileNameSize
 );
```

## References

+ Documentation of protocol [MS-FAX]: Fax Server and Client Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4

+ Documentation of function `FaxObs_GetQueueFileName`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/21d0c234-8dca-4f96-b7ea-2bdce029ee00
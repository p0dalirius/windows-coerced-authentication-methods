# MS-FAX - Remote call to FAX_StartCopyToServer (opnum 68)

## Summary

+ **Protocol**: [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)

+ **Protocol UUID**: 6099fc12-3eff-11d0-abd0-00c04fd91a4e

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\SHAREDFAX`

+ **Function name**: [`FAX_StartCopyToServer`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/d4fdc04e-6594-4563-9700-d4cc645b4335)

+ **Function operation number**: `68`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\SHAREDFAX` and bind to the desired [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol (with uuid `6099fc12-3eff-11d0-abd0-00c04fd91a4e` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol.

**This call cannot be used to coerce an authentication.** The client does not supply the file name — "**the server MUST generate a unique file name** and create a file with that name in the server queue directory" ([MS-FAX] 3.1.4.1.97). The only client-controlled input is `lpcwstrFileExt`, the file extension, and the server accepts only `.tif` or `.cov` (any other value returns `ERROR_INVALID_PARAMETER`). `lpwstrServerFileName` is an `[in, out]` buffer that the server **overwrites** with the name it chose. With no client-controlled path and the extension constrained to two literal values, there is nothing that resolves to a remote location.

## Function technical detail

```cpp
error_status_t FAX_StartCopyToServer(
   [in] handle_t hFaxHandle,
   [in, string, ref] LPCWSTR lpcwstrFileExt,
   [in, out, string, ref] LPWSTR lpwstrServerFileName,
   [out, ref] PRPC_FAX_COPY_HANDLE lpHandle
 );
```

## References

+ Documentation of protocol [MS-FAX]: Fax Server and Client Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4

+ Documentation of function `FAX_StartCopyToServer`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/d4fdc04e-6594-4563-9700-d4cc645b4335
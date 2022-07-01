![](./.github/banner.png)

---

<p align="center">
  This repository contains a list of many methods to coerce a windows machine to authenticate to an attacker-controlled machine.
  <br>
  <img alt="GitHub repo size" src="https://img.shields.io/badge/coerce%20methods-12-brightgreen">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
  <br>
</p>

All of these methods are callable by a standard user in the domain to force the machine account of the target Windows machine (usually a domain controller) to authenticate to an arbitrary target. The root cause of this "vulnerability/feature" in each of these methods is that Windows machines automatically authenticate to other machines when trying to access UNC paths (like `\\192.168.2.1\SYSVOL\file.txt`).

There is currently **12** known methods in **5** protocols.

---

## Protocols & Methods

 + **[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol**
    - [Remote call to NetrDfsRemoveStdRoot (opnum 13)](./methods/%5BMS-DFSNM%5D%20Distributed%20File%20System%20%28DFS%29%20Namespace%20Management%20Protocol/Remote%20call%20to%20NetrDfsRemoveStdRoot%20(opnum%2013)/README.md)


 + **[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol** 
    - [Remote call to EfsRpcOpenFileRaw (opnum 0)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcOpenFileRaw%20(opnum%200)/README.md) 
    - [Remote call to EfsRpcEncryptFileSrv (opnum 4)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcEncryptFileSrv%20(opnum%204)/README.md) 
    - [Remote call to EfsRpcDecryptFileSrv (opnum 5)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcDecryptFileSrv%20(opnum%205)/README.md) 
    - [Remote call to EfsRpcQueryUsersOnFile (opnum 6)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcQueryUsersOnFile%20(opnum%206)/README.md) 
    - [Remote call to EfsRpcQueryRecoveryAgents (opnum 7)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcQueryRecoveryAgents%20(opnum%207)/README.md) 
    - [Remote call to EfsRpcFileKeyInfo (opnum 12)](./methods/%5BMS-EFSR%5D%20Encrypting%20File%20System%20Remote%20%28EFSRPC%29%20Protocol/Remote%20call%20to%20EfsRpcFileKeyInfo%20(opnum%2012)/README.md) 


 + **[MS-FSRVP]: File Server Remote VSS Protocol**
    - [Remote call to IsPathSupported (opnum 8)](./methods/%5BMS-FSRVP%5D%20File%20Server%20Remote%20VSS%20Protocol/Remote%20call%20to%20IsPathShadowCopied%20(opnum%209)/Remote%20call%20to%20IsPathSupported%20(opnum%208)/README.md) 
    - [Remote call to IsPathShadowCopied (opnum 9)](./methods/%5BMS-FSRVP%5D%20File%20Server%20Remote%20VSS%20Protocol/Remote%20call%20to%20IsPathSupported%20(opnum%208)/Remote%20call%20to%20IsPathShadowCopied%20(opnum%209)/README.md)


 + **[MS-PAR]: Print System Asynchronous Remote Protocol** 
    - [Remote call to RpcAsyncOpenPrinter (opnum 0)](./methods/%5BMS-PAR%5D%20Print%20System%20Asynchronous%20Remote%20Protocol/Remote%20call%20to%20RpcAsyncOpenPrinter%20(opnum%200)/README.md) 


 + **[MS-RPRN]: Print System Remote Protocol** 
    - [Remote call to RpcOpenPrinter (opnum 1)](./methods/%5BMS-RPRN%5D%20Print%20System%20Remote%20Protocol/Remote%20call%20to%20RpcOpenPrinter%20(opnum%201)/README.md)
    - [Remote call to RpcOpenPrinterEx (opnum 69)](./methods/%5BMS-RPRN%5D%20Print%20System%20Remote%20Protocol/Remote%20call%20to%20RpcOpenPrinterEx%20(opnum%2069)/README.md)

## Contributing

Feel free to open a pull request to add new methods.

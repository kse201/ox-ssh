;;; ox-ssh.el --- SSH Config Backend for Org Export Engine -*- lexical-binding: t; -*-

;; Copyright (C) 2020 Dante Catalfamo

;; Author: Dante Catalfamo
;; Version: 2.0
;; Package-Requires: ((emacs "24.4"))
;; Keywords: outlines, org, ssh
;; Homepage: https://github.com/dantecatalfamo/ox-ssh

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; SSH configuration export for org-mode.
;;
;; Commands
;; `ox-ssh' provides the following interactive commands:
;; - `org-ssh-export-as-config' Exports to a temporary buffer
;; - `org-ssh-export-to-config' Exports to file with the extension .ssh_config
;; - `org-ssh-export-overwrite-user-config' Exports file, overwrites user's =~/.ssh/config=.
;;   Prompts user with yes/no option before doing so.
;; These commands are also exposed through the `org-export-dispatch' menu.
;;
;; Variables
;; - `org-ssh-header' An optional header that will be added to the
;;   beginning of the export. This can be used for comments or rules
;;   that apply to all hosts.
;; - `org-ssh-export-suffix' The suffix that will be added to exported file.
;;   Defaults to ".ssh_config".
;;
;; Usage
;; Export headings with specific properties as entries in an SSH
;; configuration file. These properties correspond with the client
;; configuration options for SSH.
;;
;; For a heading to be exported as a host, it must have either a
;; HOSTNAME or IP property. If an entry has both, IP takes
;; precedence. It can also contain one or more
;; optional parameters, listed in the table below.
;;
;; | ssh_config(5) option             | ox-ssh property                          |
;; |----------------------------------+------------------------------------------|
;; | AddKeysToAgent                   | SSH_ADD_KEYS_TO_AGENT                    |
;; | AddressFamily                    | SSH_ADDRESS_FAMILY                       |
;; | BatchMode                        | SSH_BATCH_MODE                           |
;; | BindInterface                    | SSH_BIND_INTERFACE                       |
;; | CanonicalDomains                 | SSH_CANONICAL_DOMAINS                    |
;; | CanonicalizeFallbackLocal        | SSH_CANONICALIZE_FALLBACK_LOCAL          |
;; | CanonicalizeHostname             | SSH_CANONICALIZE_HOSTNAME                |
;; | CanonicalizeMaxDots              | SSH_CANONICALIZE_MAX_DOTS                |
;; | CanonicalizePermittedCNAMEs      | SSH_CANONICALIZE_PERMITTED_CNAMES        |
;; | CASignatureAlgorithms            | SSH_CA_SIGNATURE_ALGORITHMS              |
;; | CertificateFile                  | SSH_CERTIFICATE_FILE                     |
;; | ChallengeResponseAuthentication  | SSH_CHALLENGE_RESPONSE_AUTHENTICATION    |
;; | CheckHostIP                      | SSH_CHECK_HOST_IP                        |
;; | Ciphers                          | SSH_CIPHERS                              |
;; | ClearAllForwardings              | SSH_CLEAR_ALL_FORWARDINGS                |
;; | Compression                      | SSH_COMPRESSION                          |
;; | ConnectionAttempts               | SSH_CONNECTION_ATTEMPTS                  |
;; | ConnectTimeout                   | SSH_CONNECT_TIMEOUT                      |
;; | ControlMaster                    | SSH_CONTROL_MASTER                       |
;; | ControlPath                      | SSH_CONTROL_PATH                         |
;; | ControlPersist                   | SSH_CONTROL_PERSIST                      |
;; | DynamicForward                   | SSH_DYNAMIC_FORWARD                      |
;; | EnableSSHKeysign                 | SSH_ENABLE_SSH_KEYSIGN                   |
;; | EscapeChar                       | SSH_ESCAPE_CHAR                          |
;; | ExitOnForwardFailure             | SSH_EXIT_ON_FORWARD_FAILURE              |
;; | FingerprintHash                  | SSH_FINGERPRINT_HASH                     |
;; | ForwardAgent                     | SSH_FORWARD_AGENT                        |
;; | ForwardX11                       | SSH_FORWARD_X11                          |
;; | ForwardX11Timeout                | SSH_FORWARD_X11_TIMEOUT                  |
;; | ForwardX11Trusted                | SSH_FORWARD_X11_TRUSTED                  |
;; | GatewayPorts                     | SSH_GATEWAY_PORTS                        |
;; | GlobalKnownHostsFile             | SSH_GLOBAL_KNOWN_HOSTS_FILE              |
;; | GSSAPIAuthentication             | SSH_GSSAPI_AUTHENTICATION                |
;; | GSSAPIDelegateCredentials        | SSH_GSSAPI_DELEGATE_CREDENTIALS          |
;; | HashKnownHosts                   | SSH_HASH_KNOWN_HOSTS                     |
;; | HostBasedAuthentication          | SSH_HOST_BASED_AUTHENTICATION            |
;; | HostBasedKeyTypes                | SSH_HOST_BASED_KEY_TYPES                 |
;; | HostKeyAlgorithms                | SSH_HOST_KEY_ALGORITHMS                  |
;; | HostKeyAlias                     | SSH_HOST_KEY_ALIAS                       |
;; | Hostname                         | SSH_HOSTNAME                             |
;; | IdentitiesOnly                   | SSH_IDENTITIES_ONLY                      |
;; | IdentityAgent                    | SSH_IDENTITY_AGENT                       |
;; | IdentityFile                     | SSH_IDENTITY_FILE                        |
;; | IgnoreUnknown                    | SSH_IGNORE_UNKNOWN                       |
;; | Include                          | SSH_INCLUDE                              |
;; | IPQoS                            | SSH_IP_QOS                               |
;; | KbdInteractiveAuthentication     | SSH_KBD_INTERACTIVE_AUTHENTICATION       |
;; | KbdInteractiveDevices            | SSH_KBD_INTERACTIVE_DEVICES              |
;; | KexAlgorithms                    | SSH_KEX_ALGORITHMS                       |
;; | LocalCommand                     | SSH_LOCAL_COMMAND                        |
;; | LocalForward                     | SSH_LOCAL_FORWARD                        |
;; | LogLevel                         | SSH_LOG_LEVEL                            |
;; | MACs                             | SSH_MACS                                 |
;; | NoHostAuthenticationForLocalhost | SSH_NO_HOST_AUTHENTICATION_FOR_LOCALHOST |
;; | NumberOfPasswordPrompts          | SSH_NUMBER_OF_PASSWORD_PROMPTS           |
;; | PasswordAuthentication           | SSH_PASSWORD_AUTHENTICATION              |
;; | PermitLocalCommand               | SSH_PERMIT_LOCAL_COMMAND                 |
;; | PKCS11Provider                   | SSH_PKCS11_PROVIDER                      |
;; | Port                             | SSH_PORT                                 |
;; | PreferredAuthentications         | SSH_PREFERRED_AUTHENTICATIONS            |
;; | ProxyCommand                     | SSH_PROXY_COMMAND                        |
;; | ProxyJump                        | SSH_PROXY_JUMP                           |
;; | ProxyUseFdPass                   | SSH_PROXY_USE_FD_PASS                    |
;; | PubkeyAcceptedKeyTypes           | SSH_PUBKEY_ACCEPTED_KEY_TYPES            |
;; | PubkeyAuthentication             | SSH_PUBKEY_AUTHENTICATION                |
;; | RekeyLimit                       | SSH_REKEY_LIMIT                          |
;; | RemoteCommand                    | SSH_REMOTE_COMMAND                       |
;; | RemoteForward                    | SSH_REMOTE_FORWARD                       |
;; | RequestTTY                       | SSH_REQUEST_TTY                          |
;; | RevokedHostKeys                  | SSH_REVOKED_HOST_KEYS                    |
;; | SecurityKeyProvider              | SSH_SECURITY_KEY_PROVIDER                |
;; | SendEnv                          | SSH_SEND_ENV                             |
;; | ServerAliveMaxCount              | SSH_SERVER_ALIVE_MAX_COUNT               |
;; | ServerAliveInterval              | SSH_SERVER_ALIVE_INTERVAL                |
;; | SetEnv                           | SSH_SET_ENV                              |
;; | StreamLocalBindMask              | SSH_STREAM_LOCAL_BIND_MASK               |
;; | StreamLocalBindUnlink            | SSH_STREAM_LOCAL_BIND_UNLINK             |
;; | StrictHostKeyChecking            | SSH_STRICT_HOST_KEY_CHECKING             |
;; | SyslogFacility                   | SSH_SYSLOG_FACILITY                      |
;; | TCPKeepAlive                     | SSH_TCP_KEEP_ALIVE                       |
;; | Tunnel                           | SSH_TUNNEL                               |
;; | TunnelDevice                     | SSH_TUNNEL_DEVICE                        |
;; | UpdateHostKeys                   | SSH_UPDATE_HOST_KEYS                     |
;; | User                             | SSH_USER                                 |
;; | UserKnownHostsFile               | SSH_USER_KNOWN_HOSTS_FILE                |
;; | VerifyHostKeyDNS                 | SSH_VERIFY_HOST_KEY_DNS                  |
;; | VisualHostKey                    | SSH_VISUAL_HOST_KEY                      |
;; | XAuthLocation                    | SSH_X_AUTH_LOCATION                      |

;;; Code:

(require 'ox)

(defgroup org-export-ssh nil
  "Options for exporting Org mode files to SSH config."
  :group 'org-export)

(defcustom org-ssh-header ""
  "Optional text to be inserted at the top of SSH config."
  :type 'text
  :group 'org-export-ssh)

(defcustom org-ssh-export-suffix ".ssh_config"
  "Suffix added to exported file."
  :type 'text
  :group 'org-export-ssh)

(defun org-ssh--user-config ()
  "Return the location of the user's SSH config."
  (expand-file-name (concat (file-name-as-directory ".ssh")
                            "config")
                    (getenv "HOME")))

(org-export-define-backend 'ssh
  '((headline . org-ssh-headline)
    (template . org-ssh-template))
  :menu-entry
  `(?s "Export to SSH config"
       ((?s "To file" org-ssh-export-to-config)
        (?S "To temporary buffer" org-ssh-export-as-config)
        (?x ,(format "To %s" (concat "~/"
                                     (file-name-as-directory ".ssh")
                                     "config"))
            org-ssh-export-overwrite-user-config))))

(defun org-ssh-headline (headline contents _info)
  "Transform HEADLINE and CONTENTS into SSH config host."
  (let* ((hostname (org-export-get-node-property :HOSTNAME headline t))
         (ip (org-export-get-node-property :IP headline t))
         (host (or (org-export-get-node-property :HOST_OVERRIDE headline t) (org-export-get-node-property :raw-value headline t)))
         (addr (or ip hostname)))
    (if addr
        (let ((ssh-add-keys-to-agent (org-export-get-node-property :SSH_ADD_KEYS_TO_AGENT headline t))
              (ssh-address-family (org-export-get-node-property :SSH_ADDRESS_FAMILY headline t))
              (ssh-batch-mode (org-export-get-node-property :SSH_BATCH_MODE headline t))
              (ssh-bind-interface (org-export-get-node-property :SSH_BIND_INTERFACE headline t))
              (ssh-canonical-domains (org-export-get-node-property :SSH_CANONICAL_DOMAINS headline t))
              (ssh-canonicalize-fallback-local (org-export-get-node-property :SSH_CANONICALIZE_FALLBACK_LOCAL headline t))
              (ssh-canonicalize-hostname (org-export-get-node-property :SSH_CANONICALIZE_HOSTNAME headline t))
              (ssh-canonicalize-max-dots (org-export-get-node-property :SSH_CANONICALIZE_MAX_DOTS headline t))
              (ssh-canonicalize-permitted-cnames (org-export-get-node-property :SSH_CANONICALIZE_PERMITTED_CNAMES headline t))
              (ssh-ca-signature-algorithms (org-export-get-node-property :SSH_CA_SIGNATURE_ALGORITHMS headline t))
              (ssh-certificate-file (org-export-get-node-property :SSH_CERTIFICATE_FILE headline t))
              (ssh-challenge-response-auth (org-export-get-node-property :SSH_CHALLENGE_RESPONSE_AUTHENTICATION headline t))
              (ssh-check-host-ip (org-export-get-node-property :SSH_CHECK_HOST_IP headline t))
              (ssh-ciphers (org-export-get-node-property :SSH_CIPHERS headline t))
              (ssh-clear-all-forwardings (org-export-get-node-property :SSH_CLEAR_ALL_FORWARDINGS headline t))
              (ssh-compression (org-export-get-node-property :SSH_COMPRESSION headline t))
              (ssh-connection-attempts (org-export-get-node-property :SSH_CONNECTION_ATTEMPTS headline t))
              (ssh-connect-timeout (org-export-get-node-property :SSH_CONNECT_TIMEOUT headline t))
              (ssh-control-master (org-export-get-node-property :SSH_CONTROL_MASTER headline t))
              (ssh-control-path (org-export-get-node-property :SSH_CONTROL_PATH headline t))
              (ssh-control-persist (org-export-get-node-property :SSH_CONTROL_PERSIST headline t))
              (ssh-dynamic-forward (org-export-get-node-property :SSH_DYNAMIC_FORWARD headline t))
              (ssh-enable-ssh-keysign (org-export-get-node-property :SSH_ENABLE_SSH_KEYSIGN headline t))
              (ssh-escape-char (org-export-get-node-property :SSH_ESCAPE_CHAR headline t))
              (ssh-exit-on-forward-failure (org-export-get-node-property :SSH_EXIT_ON_FORWARD_FAILURE headline t))
              (ssh-fingerprint-hash (org-export-get-node-property :SSH_FINGERPRINT_HASH headline t))
              (ssh-forward-agent (org-export-get-node-property :SSH_FORWARD_AGENT headline t))
              (ssh-forward-x11 (org-export-get-node-property :SSH_FORWARD_X11 headline t))
              (ssh-forward-x11-timeout (org-export-get-node-property :SSH_FORWARD_X11_TIMEOUT headline t))
              (ssh-forward-x11-trusted (org-export-get-node-property :SSH_FORWARD_X11_TRUSTED headline t))
              (ssh-gateway-ports (org-export-get-node-property :SSH_GATEWAY_PORTS headline t))
              (ssh-global-known-hosts-file (org-export-get-node-property :SSH_GLOBAL_KNOWN_HOSTS_FILE headline t))
              (ssh-gssapi-auth (org-export-get-node-property :SSH_GSSAPI_AUTHENTICATION headline t))
              (ssh-gssapi-delegate-credentials (org-export-get-node-property :SSH_GSSAPI_DELEGATE_CREDENTIALS headline t))
              (ssh-hash-known-hosts (org-export-get-node-property :SSH_HASH_KNOWN_HOSTS headline t))
              (ssh-host-based-auth (org-export-get-node-property :SSH_HOST_BASED_AUTHENTICATION headline t))
              (ssh-host-based-key-types (org-export-get-node-property :SSH_HOST_BASED_KEY_TYPES headline t))
              (ssh-host-key-algos (org-export-get-node-property :SSH_HOST_KEY_ALGORITHMS headline t))
              (ssh-host-key-alias (org-export-get-node-property :SSH_HOST_KEY_ALIAS headline t))
              (ssh-hostname (org-export-get-node-property :SSH_HOSTNAME headline t))
              (ssh-identities-only (org-export-get-node-property :SSH_IDENTITIES_ONLY headline t))
              (ssh-identity-agent (org-export-get-node-property :SSH_IDENTITY_AGENT headline t))
              (ssh-identity-file (org-export-get-node-property :SSH_IDENTITY_FILE headline t))
              (ssh-ignore-unknown (org-export-get-node-property :SSH_IGNORE_UNKNOWN headline t))
              (ssh-include (org-export-get-node-property :SSH_INCLUDE headline t))
              (ssh-ip-qos (org-export-get-node-property :SSH_IP_QOS headline t))
              (ssh-kbd-interactive-auth (org-export-get-node-property :SSH_KBD_INTERACTIVE_AUTHENTICATION headline t))
              (ssh-kbd-interactive-devices (org-export-get-node-property :SSH_KBD_INTERACTIVE_DEVICES headline t))
              (ssh-kex-algos (org-export-get-node-property :SSH_KEX_ALGORITHMS headline t))
              (ssh-local-command (org-export-get-node-property :SSH_LOCAL_COMMAND headline t))
              (ssh-local-forward (org-export-get-node-property :SSH_LOCAL_FORWARD headline t))
              (ssh-log-level (org-export-get-node-property :SSH_LOG_LEVEL headline t))
              (ssh-macs (org-export-get-node-property :SSH_MACS headline t))
              (ssh-no-host-auth-for-localhost (org-export-get-node-property :SSH_NO_HOST_AUTHENTICATION_FOR_LOCALHOST headline t))
              (ssh-number-of-password-prompts (org-export-get-node-property :SSH_NUMBER_OF_PASSWORD_PROMPTS headline t))
              (ssh-password-auth (org-export-get-node-property :SSH_PASSWORD_AUTHENTICATION headline t))
              (ssh-permit-local-command (org-export-get-node-property :SSH_PERMIT_LOCAL_COMMAND headline t))
              (ssh-pkcs11-provider (org-export-get-node-property :SSH_PKCS11_PROVIDER headline t))
              (ssh-port (org-export-get-node-property :SSH_PORT headline t))
              (ssh-preferred-auths (org-export-get-node-property :SSH_PREFERRED_AUTHENTICATIONS headline t))
              (ssh-proxy-command (org-export-get-node-property :SSH_PROXY_COMMAND headline t))
              (ssh-proxy-jump (org-export-get-node-property :SSH_PROXY_JUMP headline t))
              (ssh-proxy-use-fd-pass (org-export-get-node-property :SSH_PROXY_USE_FD_PASS headline t))
              (ssh-pubkey-accepted-key-types (org-export-get-node-property :SSH_PUBKEY_ACCEPTED_KEY_TYPES headline t))
              (ssh-pubkkey-auth (org-export-get-node-property :SSH_PUBKEY_AUTHENTICATION headline t))
              (ssh-rekey-limit (org-export-get-node-property :SSH_REKEY_LIMIT headline t))
              (ssh-remote-command (org-export-get-node-property :SSH_REMOTE_COMMAND headline t))
              (ssh-remote-forward (org-export-get-node-property :SSH_REMOTE_FORWARD headline t))
              (ssh-request-tty (org-export-get-node-property :SSH_REQUEST_TTY headline t))
              (ssh-revoked-host-keys (org-export-get-node-property :SSH_REVOKED_HOST_KEYS headline t))
              (ssh-security-key-provider (org-export-get-node-property :SSH_SECURITY_KEY_PROVIDER headline t))
              (ssh-send-env (org-export-get-node-property :SSH_SEND_ENV headline t))
              (ssh-server-alive-max-count (org-export-get-node-property :SSH_SERVER_ALIVE_MAX_COUNT headline t))
              (ssh-server-alive-interval (org-export-get-node-property :SSH_SERVER_ALIVE_INTERVAL headline t))
              (ssh-set-env (org-export-get-node-property :SSH_SET_ENV headline t))
              (ssh-stream-local-bind-mask (org-export-get-node-property :SSH_STREAM_LOCAL_BIND_MASK headline t))
              (ssh-stream-local-bind-unlink (org-export-get-node-property :SSH_STREAM_LOCAL_BIND_UNLINK headline t))
              (ssh-strict-host-key-checking (org-export-get-node-property :SSH_STRICT_HOST_KEY_CHECKING headline t))
              (ssh-syslog-facility (org-export-get-node-property :SSH_SYSLOG_FACILITY headline t))
              (ssh-tcp-keep-alive (org-export-get-node-property :SSH_TCP_KEEP_ALIVE headline t))
              (ssh-tunnel (org-export-get-node-property :SSH_TUNNEL headline t))
              (ssh-tunnel-device (org-export-get-node-property :SSH_TUNNEL_DEVICE headline t))
              (ssh-update-host-keys (org-export-get-node-property :SSH_UPDATE_HOST_KEYS headline t))
              (ssh-user (org-export-get-node-property :SSH_USER headline t))
              (ssh-user-known-hosts-file (org-export-get-node-property :SSH_USER_KNOWN_HOSTS_FILE headline t))
              (ssh-verify-host-key-dns (org-export-get-node-property :SSH_VERIFY_HOST_KEY_DNS headline t))
              (ssh-visual-host-key (org-export-get-node-property :SSH_VISUAL_HOST_KEY headline t))
              (ssh-x-auth-location (org-export-get-node-property :SSH_X_AUTH_LOCATION headline t)))

          (concat "\nHost " host "\n"
                  "  HostName " addr "\n"
                  (when ssh-add-keys-to-agent
                    (concat "  AddKeysToAgent " ssh-add-keys-to-agent "\n"))
                  (when ssh-address-family
                    (concat "  AddressFamily " ssh-address-family "\n"))
                  (when ssh-batch-mode
                    (concat "  BatchMode " ssh-batch-mode "\n"))
                  (when ssh-bind-interface
                    (concat "  BindInterface " ssh-bind-interface "\n"))
                  (when ssh-canonical-domains
                    (concat "  CanonicalDomains " ssh-canonical-domains "\n"))
                  (when ssh-canonicalize-fallback-local
                    (concat "  CanonicalizeFallbackLocal" ssh-canonicalize-fallback-local "\n"))
                  (when ssh-canonicalize-hostname
                    (concat "  CanonicalizeHostname " ssh-canonicalize-hostname "\n"))
                  (when ssh-canonicalize-max-dots
                    (concat "  CanonicalizeMaxDots " ssh-canonicalize-max-dots "\n"))
                  (when ssh-canonicalize-permitted-cnames
                    (concat "  CanonicalizePermittedCNAMEs " ssh-canonicalize-permitted-cnames "\n"))
                  (when ssh-ca-signature-algorithms
                    (concat "  CASignatureAlgorithms " ssh-ca-signature-algorithms "\n"))
                  (when ssh-certificate-file
                    (concat "  CertificateFile " ssh-certificate-file "\n"))
                  (when ssh-challenge-response-auth
                    (concat "  ChallengeResponseAuthentication " ssh-challenge-response-auth "\n"))
                  (when ssh-check-host-ip
                    (concat "  CheckHostIP " ssh-check-host-ip "\n"))
                  (when ssh-ciphers
                    (concat "  Ciphers " ssh-ciphers "\n"))
                  (when ssh-clear-all-forwardings
                    (concat "  ClearAllForwardings " ssh-clear-all-forwardings "\n"))
                  (when ssh-compression
                    (concat "  Compression " ssh-compression "\n"))
                  (when ssh-connection-attempts
                    (concat "  ConnectionAttempts " ssh-connection-attempts "\n"))
                  (when ssh-connect-timeout
                    (concat "  ConnectTimeout " ssh-connect-timeout "\n"))
                  (when ssh-control-master
                    (concat "  ControlMaster " ssh-control-master "\n"))
                  (when ssh-control-path
                    (concat "  ControlPath " ssh-control-path "\n"))
                  (when ssh-control-persist
                    (concat "  ControlPersist " ssh-control-persist "\n"))
                  (when ssh-dynamic-forward
                    (concat "  DynamicForward " ssh-dynamic-forward "\n"))
                  (when ssh-enable-ssh-keysign
                    (concat "  EnableSSHKeysign " ssh-enable-ssh-keysign "\n"))
                  (when ssh-escape-char
                    (concat "  EscapeChar " ssh-escape-char "\n"))
                  (when ssh-exit-on-forward-failure
                    (concat "  ExitOnForwardFailure " ssh-exit-on-forward-failure "\n"))
                  (when ssh-fingerprint-hash
                    (concat "  FingerprintHash " ssh-fingerprint-hash "\n"))
                  (when ssh-forward-agent
                    (concat "  ForwardAgent " ssh-forward-agent "\n"))
                  (when ssh-forward-x11
                    (concat "  ForwardX11 " ssh-forward-x11 "\n"))
                  (when ssh-forward-x11-timeout
                    (concat "  ForwardX11Timeout " ssh-forward-x11-timeout "\n"))
                  (when ssh-forward-x11-trusted
                    (concat "  ForwardX11Trusted " ssh-forward-x11-trusted "\n"))
                  (when ssh-gateway-ports
                    (concat "  GatewayPorts " ssh-gateway-ports "\n"))
                  (when ssh-global-known-hosts-file
                    (concat "  GlobalKnownHostsFile " ssh-global-known-hosts-file "\n"))
                  (when ssh-gssapi-auth
                    (concat "  GSSAPIAuthentication " ssh-gssapi-auth "\n"))
                  (when ssh-gssapi-delegate-credentials
                    (concat "  GSSAPIDelegateCredentials " ssh-gssapi-delegate-credentials "\n"))
                  (when ssh-hash-known-hosts
                    (concat "  HashKnownHosts " ssh-hash-known-hosts "\n"))
                  (when ssh-host-based-auth
                    (concat "  HostbasedAuthentication " ssh-host-based-auth "\n"))
                  (when ssh-host-based-key-types
                    (concat "  HostbasedKeyTypes " ssh-host-based-key-types "\n"))
                  (when ssh-host-key-algos
                    (concat "  HostKeyAlgorithms " ssh-host-key-algos "\n"))
                  (when ssh-host-key-alias
                    (concat "  HostKeyAlias " ssh-host-key-alias "\n"))
                  (when ssh-hostname
                    (concat "  Hostname " ssh-hostname "\n"))
                  (when ssh-identities-only
                    (concat "  IdentitiesOnly " ssh-identities-only "\n"))
                  (when ssh-identity-agent
                    (concat "  IdentityAgent " ssh-identity-agent "\n"))
                  (when ssh-identity-file
                    (concat "  IdentityFile " ssh-identity-file "\n"))
                  (when ssh-ignore-unknown
                    (concat "  IgnoreUnknown " ssh-ignore-unknown "\n"))
                  (when ssh-include
                    (concat "  Include " ssh-include "\n"))
                  (when ssh-ip-qos
                    (concat "  IPQoS " ssh-ip-qos "\n"))
                  (when ssh-kbd-interactive-auth
                    (concat "  KbdInteractiveAuthentication " ssh-kbd-interactive-auth "\n"))
                  (when ssh-kbd-interactive-devices
                    (concat "  KbdInteractiveDevices " ssh-kbd-interactive-devices "\n"))
                  (when ssh-kex-algos
                    (concat "  KexAlgorithms " ssh-kex-algos "\n"))
                  (when ssh-local-command
                    (concat "  LocalCommand " ssh-local-command "\n"))
                  (when ssh-local-forward
                    (concat "  LocalForward " ssh-local-forward "\n"))
                  (when ssh-log-level
                    (concat "  LogLevel " ssh-log-level "\n"))
                  (when ssh-macs
                    (concat "  MACs " ssh-macs "\n"))
                  (when ssh-no-host-auth-for-localhost
                    (concat "  NoHostAuthenticationForLocalhost " ssh-no-host-auth-for-localhost "\n"))
                  (when ssh-number-of-password-prompts
                    (concat "  NumberOfPasswordPrompts " ssh-number-of-password-prompts "\n"))
                  (when ssh-password-auth
                    (concat "  PasswordAuthentication " ssh-password-auth "\n"))
                  (when ssh-permit-local-command
                    (concat "  PermitLocalCommand " ssh-permit-local-command "\n"))
                  (when ssh-pkcs11-provider
                    (concat "  PKCS11Provider " ssh-pkcs11-provider "\n"))
                  (when ssh-port
                    (concat "  Port " ssh-port "\n"))
                  (when ssh-preferred-auths
                    (concat "  PreferredAuthentications " ssh-preferred-auths "\n"))
                  (when ssh-proxy-command
                    (concat "  ProxyCommand " ssh-proxy-command "\n"))
                  (when ssh-proxy-jump
                    (concat "  ProxyJump " ssh-proxy-jump "\n"))
                  (when ssh-proxy-use-fd-pass
                    (concat "  ProxyUseFdpass " ssh-proxy-use-fd-pass "\n"))
                  (when ssh-pubkey-accepted-key-types
                    (concat "  PubkeyAcceptedKeyTypes " ssh-pubkey-accepted-key-types "\n"))
                  (when ssh-pubkkey-auth
                    (concat "  PubkeyAuthentication " ssh-pubkkey-auth "\n"))
                  (when ssh-rekey-limit
                    (concat "  RekeyLimit " ssh-rekey-limit "\n"))
                  (when ssh-remote-command
                    (concat "  RemoteCommand " ssh-remote-command "\n"))
                  (when ssh-remote-forward
                    (concat "  RemoteForward " ssh-remote-forward "\n"))
                  (when ssh-request-tty
                    (concat "  RequestTTY " ssh-request-tty "\n"))
                  (when ssh-revoked-host-keys
                    (concat "  RevokedHostKeys " ssh-revoked-host-keys "\n"))
                  (when ssh-security-key-provider
                    (concat "  SecurityKeyProvider " ssh-security-key-provider "\n"))
                  (when ssh-send-env
                    (concat "  SendEnv " ssh-send-env "\n"))
                  (when ssh-server-alive-max-count
                    (concat "  ServerAliveCountMax " ssh-server-alive-max-count "\n"))
                  (when ssh-server-alive-interval
                    (concat "  ServerAliveInterval " ssh-server-alive-interval "\n"))
                  (when ssh-set-env
                    (concat "  SetEnv " ssh-set-env "\n"))
                  (when ssh-stream-local-bind-mask
                    (concat "  StreamLocalBindMask " ssh-stream-local-bind-mask "\n"))
                  (when ssh-stream-local-bind-unlink
                    (concat "  StreamLocalBindUnlink " ssh-stream-local-bind-unlink "\n"))
                  (when ssh-strict-host-key-checking
                    (concat "  StrictHostKeyChecking " ssh-strict-host-key-checking "\n"))
                  (when ssh-syslog-facility
                    (concat "  SyslogFacility " ssh-syslog-facility "\n"))
                  (when ssh-tcp-keep-alive
                    (concat "  TCPKeepAlive " ssh-tcp-keep-alive "\n"))
                  (when ssh-tunnel
                    (concat "  Tunnel " ssh-tunnel "\n"))
                  (when ssh-tunnel-device
                    (concat "  TunnelDevice " ssh-tunnel-device "\n"))
                  (when ssh-update-host-keys
                    (concat "  UpdateHostKeys " ssh-update-host-keys "\n"))
                  (when ssh-user
                    (concat "  User " ssh-user "\n"))
                  (when ssh-user-known-hosts-file
                    (concat "  UserKnownHostsFile " ssh-user-known-hosts-file "\n"))
                  (when ssh-verify-host-key-dns
                    (concat "  VerifyHostKeyDNS " ssh-verify-host-key-dns "\n"))
                  (when ssh-visual-host-key
                    (concat "  VisualHostKey " ssh-visual-host-key "\n"))
                  (when ssh-x-auth-location
                    (concat "  XAuthLocation " ssh-x-auth-location "\n"))
                  contents))
      contents)))

(defun org-ssh-template (contents _info)
  "Transform CONTENTS into SSH config with header."
  (string-trim-left (concat org-ssh-header "\n"
                            (replace-regexp-in-string "\n\n\n+" "\n\n" contents))))

;;;###autoload
(defun org-ssh-export-as-config (&optional ASYNC SUBTREEP VISIBLE-ONLY BODY-ONLY EXT-PLIST)
  "Export current buffer to an SSH config buffer.

If narrowing is active in the current buffer, only transcode its
narrowed part.

If a region is active, transcode that region.

A non-nil optional argument ASYNC means the process should happen
asynchronously.  The resulting buffer should be accessible
through the `org-export-stack' interface.

When optional argument SUBTREEP is non-nil, transcode the
sub-tree at point, extracting information from the headline
properties first.

When optional argument VISIBLE-ONLY is non-nil, don't export
contents of hidden elements.

When optional argument BODY-ONLY is non-nil, only return body
code, without surrounding template.

Optional argument EXT-PLIST, when provided, is a property list
with external parameters overriding Org default settings, but
still inferior to file-local settings."
  (interactive)
  (org-export-to-buffer 'ssh "*Org SSH Export*"
    ASYNC SUBTREEP VISIBLE-ONLY BODY-ONLY EXT-PLIST
    (lambda () (conf-mode))))

;;;###autoload
(defun org-ssh-export-to-config (&optional async subtreep visible-only body-only ext-plist)
  "Export current buffer to an SSH config file.

If narrowing is active in the current buffer, only transcode its
narrowed part.

If a region is active, transcode that region.

A non-nil optional argument ASYNC means the process should happen
asynchronously.  The resulting buffer should be accessible
through the `org-export-stack' interface.

When optional argument SUBTREEP is non-nil, transcode the
sub-tree at point, extracting information from the headline
properties first.

When optional argument VISIBLE-ONLY is non-nil, don't export
contents of hidden elements.

When optional argument BODY-ONLY is non-nil, only return body
code, without surrounding template.

Optional argument EXT-PLIST, when provided, is a property list
with external parameters overriding Org default settings, but
still inferior to file-local settings.

Return output file's name."
  (interactive)
  (let ((outfile (org-export-output-file-name org-ssh-export-suffix subtreep)))
    (org-export-to-file 'ssh outfile async subtreep visible-only body-only ext-plist)))

;;;###autoload
(defun org-ssh-export-overwrite-user-config (&optional async subtreep visible-only body-only ext-plist)
  "Export current buffer as an SSH config file, overwriting $HOME/.ssh/config.

If narrowing is active in the current buffer, only transcode its
narrowed part.

If a region is active, transcode that region.

A non-nil optional argument ASYNC means the process should happen
asynchronously.  The resulting buffer should be accessible
through the `org-export-stack' interface.

When optional argument SUBTREEP is non-nil, transcode the
sub-tree at point, extracting information from the headline
properties first.

When optional argument VISIBLE-ONLY is non-nil, don't export
contents of hidden elements.

When optional argument BODY-ONLY is non-nil, only return body
code, without surrounding template.

Optional argument EXT-PLIST, when provided, is a property list
with external parameters overriding Org default settings, but
still inferior to file-local settings.

Return output file's name."
  (interactive)
  (let ((outfile (org-ssh--user-config)))
    (when (yes-or-no-p (format "Overwrite %s? " outfile))
      (org-export-to-file 'ssh outfile async subtreep visible-only body-only ext-plist
                          (lambda (file) (set-file-modes file #o600))))))

(provide 'ox-ssh)
;;; ox-ssh.el ends here

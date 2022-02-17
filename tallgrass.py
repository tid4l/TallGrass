#!/usr/bin/env python3
# 
# TallGrass
# By chdav
#   Credit to Impacket (by SecureAuth) + their examples

import argparse
import sys
import time
from colorama import init, Fore, Style
from impacket.dcerpc.v5 import transport, rrp, scmr, samr
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES

class HostEnumeration:
    def __init__(self, username, password, domain, hashes=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__machinesList = list()
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self):
        domainController = self.__domain

        print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Retrieving host list from " + Fore.CYAN + domainController)
        rpctransport = transport.SMBTransport(domainController, 445, r'\samr', self.__username, self.__password,
                                              self.__domain, self.__lmhash, self.__nthash)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
        except:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] DC unreachable")
            exit()
        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle'] 

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT,
                                                            enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    self.__machinesList.append(user['Name'][:-1])

                enumerationContext = resp['EnumerationContext'] 
                status = resp['ErrorCode']
        except Exception:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] Unable to retrieve host list")

        dce.disconnect()
        return self.__machinesList
        

class RemoteConnections:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None

        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None

    def getRRP(self):
        return self.__rrp

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Check service status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            print("[" + Fore.YELLOW + "Caution" + Fore.RESET + "] Service \'" + self.__serviceName + "\' is in stopped state")
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            self.__shouldStop = False
            self.__started = True
        else:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] Unknown service state 0x" + ans['CurrentState'] + " - Aborting")

        # Check service configuration to see if service is stopped
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                print("[" + Fore.YELLOW + "Caution" + Fore.RESET + "] Service \'" + self.__serviceName + "\' is disabled, enabling it")

                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
            print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Starting service \'" + self.__serviceName + "\'")
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.connectWinReg()

    def __restore(self):
        # Restores service to original state
        if self.__shouldStop is True:
            print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Stopping service \'" + self.__serviceName + "\'")
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Restoring disabled state for service \'" + self.__serviceName + "\'")

            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x4)

    def finish(self):
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__scmr is not None:
            self.__scmr.disconnect()


class RegistryHandler:
    def __init__(self, username, password, domain, rootKeys, subKeys):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__rootKeys= rootKeys
        self.__subKeys = subKeys
        self.__port = '445'
        self.__lmhash = ''
        self.__nthash = ''
        self.__smbConnection = None
        self.__remoteConn = None

        if args.n is not None:
            self.__lmhash, self.__nthash = args.n.split(':')

    def connect(self, remoteName, remoteHost):
        self.__smbConnection = SMBConnection(remoteName, remoteHost, sess_port=int(self.__port))

        self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def run(self, remoteName, remoteHost):
        try:
            self.connect(remoteName, remoteHost)
            self.__remoteConn = RemoteConnections(self.__smbConnection)

            try:
                self.__remoteConn.enableRegistry()
            except:
                print("[" + Fore.RED + "Error" + Fore.RESET + "] Cannot check RemoteRegistry status")
                self.__remoteConn.connectWinReg()
            print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Enumerating antivirus products")
            for av_product in self.__rootKeys:
                try:
                    dce = self.__remoteConn.getRRP()
                    try:
                        self.query(dce, self.__rootKeys[av_product])
                        print(Style.BRIGHT + "[" + Fore.MAGENTA + "Antivirus" + Fore.RESET + "] " + av_product + " detected")
                    except:
                        continue
                    for subKey in self.__subKeys:
                        print("[" + Fore.GREEN + "Info" + Fore.RESET + "] "+ av_product + ": Querying \'" + subKey[1:] + "\' for exclusions")
                        self.query(dce, self.__rootKeys[av_product] + subKey)

                
                except (Exception, KeyboardInterrupt) as e:
                    print("[" + Fore.RED + "Error" + Fore.RESET + "] " + str(e))
        
        except:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] Unable to connect. Host may be offline.")
        finally:
                if self.__remoteConn:
                    self.__remoteConn.finish()

    def query(self, dce, keyName):
        try:
            rootKey = keyName.split('\\')[0]
            subKey = '\\'.join(keyName.split('\\')[1:])
        except:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] Unable to parse keyName \'" + keyName + "\'")

        if rootKey.upper() == 'HKLM':
            ans = rrp.hOpenLocalMachine(dce)
        elif rootKey.upper() == 'HKU':
            ans = rrp.hOpenCurrentUser(dce)
        elif rootKey.upper() == 'HKCR':
            ans = rrp.hOpenClassesRoot(dce)
        else:
            print("[" + Fore.RED + "Error" + Fore.RESET + "] Invalid root key: " + rootKey)

        hRootKey = ans['phKey']

        ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey,
                                   samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)

        self.__print_key_values(dce, ans2['phkResult'])

    def __print_key_values(self, rpc, keyHandler):
        i = 0
        while True:
            try:
                ans4 = rrp.hBaseRegEnumValue(rpc, keyHandler, i)
                lp_value_name = ans4['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                lp_type = ans4['lpType']
                lp_data = b''.join(ans4['lpData'])
                print(Style.BRIGHT + "[" + Fore.GREEN + "Exclusion" + Fore.RESET + "] " + lp_value_name)
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break


def banner():
    print(Style.BRIGHT + Fore.GREEN + "\n            ░")
    print(Style.BRIGHT + Fore.GREEN + "                 ░░")
    print(Style.BRIGHT + Fore.GREEN + "                    ░░")
    print(Style.BRIGHT + Fore.GREEN + "        ░             ░░             ░")
    print(Style.BRIGHT + Fore.GREEN + "         ░            ░░░░        ░░     ░")
    print(Style.BRIGHT + Fore.CYAN + "      _____     _ _  ___ " + Style.BRIGHT + Fore.GREEN + "     ░░░░    ░░")
    print(Style.BRIGHT + Fore.GREEN + "   ▒" + Style.BRIGHT + Fore.CYAN + " |_   _|_ _| | |/ __|_ _ __ _ ______")
    print(Style.BRIGHT + Fore.GREEN + "    ▒" + Style.BRIGHT + Fore.CYAN + "  | |/ _` | | | (_ | '_/ _` (_-<_-<")
    print(Style.BRIGHT + Fore.GREEN + "      ░" + Style.BRIGHT + Fore.CYAN + "|_|\__,_|_|_|\___|_| \__,_/__/__/" + Style.BRIGHT + Fore.GREEN + "  ▒")
    print(Style.BRIGHT + Fore.GREEN + "      ▒▒    ░░  ▒▒    ▒▒  ░░  ▒▒  ▒▒    ░░")
    print(Style.BRIGHT + Fore.GREEN + "      ░░░░  ▒▒  ▒▒░░░░▒▒░░░░ ▓░░▓▓░░  ▒▒")
    print(Style.BRIGHT + Fore.GREEN + "     ▒▒▓▓▒▒▒▒▓▒▓▓▒▒▒▒▒▒▓▒▒▒▒▓▓▒▒▓▓▒▒▒▒▒░░\n")
    print("\t      TallGrass v0.0.1\n\n")

def args():
    parser = argparse.ArgumentParser(add_help=True, description="Windows domain AV exclusion enumeration.")

    group = parser.add_argument_group('required arguments')

    group.add_argument("-u", metavar="USERNAME", action="store", required=True, help='Domain username')
    group.add_argument("-d", metavar="DC FQDN", action="store", required=True, help='Target Domain Controller FQDN, I.E. dc-1.example.local')
 
    group = parser.add_argument_group('authentication')

    group.add_argument('-n', metavar="LMHASH:NTHASH", action="store", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-p', metavar="PASSWORD", action="store", help="Cleartext password")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def start(username, password, hashes, domain_controller, av_keys, sub_keys):
    domain_controller = domain_controller.upper()
    dc_split = domain_controller.split(".")
    
    domain_computers = list()
    domain_computers.append(dc_split[0])

    # Enumerate domain hosts
    host_enum = HostEnumeration(username, password, domain_controller, hashes)
    domain_computers.extend(host_enum.run())

    print("[" + Fore.GREEN + "Info" + Fore.RESET + "] Found " + Fore.CYAN + str(len(domain_computers)) + Fore.RESET +" computers")

    # For each host, check AV present and enumerate exclusions
    for host in domain_computers:
        remote_name = host + "." + ".".join(dc_split[1:])
        print("\t" + Style.BRIGHT + Fore.CYAN + remote_name)
        regHandler = RegistryHandler(username, password, dc_split[1], av_keys, sub_keys)
        try:
            regHandler.run(remote_name, remote_name)
        except Exception as e:
            print(str(e))

if __name__ == '__main__':

    init(autoreset=True)
    banner()
    args = args()

    username = args.u
    password = args.p
    hashes = args.n

    domain_controller = args.d
    
    ### Add paths for other AVs here
    defender_root_key = "HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions"
    essentials_root_key = "HKLM\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions"

    av_keys = {"Windows Defender":defender_root_key, "Microsoft Essentials":essentials_root_key}
    sub_keys = ["\\Paths", "\\Processes", "\\Extensions"]
    ###
    
    if password is None and hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    start(username, password, hashes, domain_controller, av_keys, sub_keys)
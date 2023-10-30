
from impacket.examples import utils
from getpass import getpass

import argparse
import sys
import os

from abuseACL.structures.Credentials import Credentials
from abuseACL.structures.Target import Target
from abuseACL.core.abuseACL import abuseACL
from abuseACL.core.Logger import Logger
from abuseACL.network.LDAP import LDAP
from abuseACL import __banner__

class Arguments:

    debug: bool
    ts: bool
    no_pass: bool
    hashes: str
    doKerberos: bool
    aesKey: bool
    dc_ip: str
    port: int
    domain: str
    username: str
    password: str
    remote_name: str
    principal: str
    principalsfile: str
    forest: str

    def __init__(self) -> None:
        self.__parser = argparse.ArgumentParser(add_help=True, description="Automatic Windows vulnerable ACEs/ACLs listing")
        self.__parser.add_argument("-debug", default=False, action="store_true", help="Turn DEBUG output ON. (Default: False)")
        self.__parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")

        # Credentials
        credentials = self.__parser.add_argument_group("Credentials")
        credentials.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for -k or when using proxychains)")
        credentials.add_argument("-hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes. LM hash can be empty.")
        credentials.add_argument("-k", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
        credentials.add_argument("-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")

        # Connection
        connection = self.__parser.add_argument_group("Connection")
        connection.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
        connection.add_argument("-port", type=int, action="store", help="Port of the domain controller. If omitted it will try to authenticate in LDAPS and then in LDAP.")

        # User
        filters = self.__parser.add_argument_group("Filters")
        filters.add_argument("-principal", action="store", help="Find vulnerable ACE for a specific User/Computer/Group")
        filters.add_argument("-principalsfile", action="store", help="File with multiple User/Computer/Group")
        filters.add_argument("-forest", action="store", help="Forest to use if different from dc. Not implemented yet.")

        self.__parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")

    def parseArgs(self) -> None:
        if len(sys.argv) == 1:
            self.__parser.print_help()
            sys.exit(1)

        self._args          = self.__parser.parse_args()
        self.debug          = self._args.debug
        self.ts             = self._args.ts
        self.no_pass        = self._args.no_pass
        self.hashes         = self._args.hashes
        self.doKerberos     = self._args.k
        self.aesKey         = self._args.aesKey
        self.dc_ip          = self._args.dc_ip
        self.port           = self._args.port
        self.principal      = self._args.principal
        self.principalsfile = self._args.principalsfile
        self.forest         = self._args.forest

        self.domain, self.username, self.password, self.remote_name = utils.parse_target(self._args.target)
        if not len(self.domain):
            self.domain, self.username, self.password = utils.parse_credentials(self._args.target)
            self.remote_name = None
        
        if not len(self.password) and self.hashes is None and not self.no_pass and self.aesKey is None:
            self.password = getpass("Password:")

        if self.hashes is None:
            self.hashes = ""
        
        if ":" not in self.hashes and len(self.hashes):
            self.hashes = "aad3b435b51404eeaad3b435b51404ee:%s" % (self.hashes)
        
        if self.principalsfile:
            if not os.path.exists(self.principalsfile):
                Logger().error(f"File {self.principalsfile} doesn't exists")
                exit(1)
            
            if not os.path.isfile(self.principalsfile):
                Logger().error(f"File {self.principalsfile} is not a file")
                exit(1)
            
            with open(self.principalsfile) as f:
                self.principalsfile = f.read().splitlines()

def main():
    print(__banner__)

    arguments = Arguments()
    arguments.parseArgs()

    logger = Logger(arguments.debug, arguments.ts)
    credentials = Credentials(arguments.username, arguments.password, arguments.domain, arguments.hashes, arguments.aesKey, arguments.doKerberos)
    target = Target(arguments.dc_ip or arguments.remote_name or arguments.domain, arguments.port)
    ldap = LDAP(arguments.forest, target, credentials, logger)

    acl = abuseACL(ldap, logger)

    # One specific account
    if arguments.principal:
        acl.abuse(arguments.principal)
    # Multiple accounts
    elif arguments.principalsfile:
        for principal in arguments.principalsfile:
            acl.abuse(principal)
    # Default
    else:
        acl.abuse(arguments.username)


from typing import List

import ssl as tls
import ldap3

from abuseACL.structures.sAMAccountType import sAMAccountType
from abuseACL.structures.Credentials import Credentials
from abuseACL.structures.Target import Target
from abuseACL.structures.ADObject.ADCertificateTemplate import ADCertificateTemplate
from abuseACL.structures.ADObject.ADAdminSDHolder import ADAdminSDHolder
from abuseACL.structures.ADObject.ADContainer import ADContainer
from abuseACL.structures.ADObject.ADComputer import ADComputer
from abuseACL.structures.ADObject.ADDomain import ADDomain
from abuseACL.structures.ADObject.ADSchema import ADSchema
from abuseACL.structures.ADObject.ADGroup import ADGroup
from abuseACL.structures.ADObject.ADUser import ADUser
from abuseACL.structures.ADObject.ADgMSA import ADgMSA
from abuseACL.structures.ADObject.ADGPO import ADGPO
from abuseACL.structures.ADObject.ADOU import ADOU
from abuseACL.structures.ADObject import ADObject
from abuseACL.structures.structures import WELL_KNOWN_SID
from abuseACL.network.Kerberos import Kerberos
from abuseACL.core.Logger import Logger

class LDAP:

    users = list()
    groups = list()
    computers = list()
    certificatesTemplates = list()
    gpos = list()
    ous = list()
    containers = list()
    adminSDHolder = list()
    schema = list()
    gMSA = list()
    domain: ADDomain = None

    def __init__(self, forest: str, target: Target, credentials: Credentials, logger: Logger) -> None:
        self.target         = target
        self.credentials    = credentials
        self.logger         = logger

        self.__getPort()
        self.__checkAuthentication()

    def __getPort(self) -> None:
        if self.target.port:
            return

        self.target.port, self.target.tlsv1_2 = self.__tryLDAPS(tls.PROTOCOL_TLSv1_2, self.target.port)

        if self.target.tlsv1_2 is None:
            self.target.port, self.target.tlsv1 = self.__tryLDAPS(tls.PROTOCOL_TLSv1, self.target.port)

            if self.target.tlsv1 is None:
                self.target.port = self.__tryLDAP(self.target.port)

        if self.target.port is None:
            self.logger.error(f"Impossible to communicate with the target {self.target.remote} !")
            exit(1)

    def __checkAuthentication(self) -> None:
        self.logger.print("Trying to connect to %s:%d" % (self.target.remote, self.target.port))
        self.__Authentication()

        try:
            self.getNamingContexts()
        except IndexError:
            self.logger.error("Invalid credentials !")
            exit(1)

        self.logger.print("Authentication success !")

    def __Authentication(self) -> ldap3.Connection:
        user = "%s\\%s" % (self.credentials.domain, self.credentials.username)

        ldapTls = None

        if self.target.tlsv1_2:
            ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=tls.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')
        elif self.target.tlsv1:
            ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=tls.PROTOCOL_TLSv1, ciphers='ALL:@SECLEVEL=0')
        
        ldapServer = ldap3.Server(self.target.remote, use_ssl=self.target.use_tls(), port=self.target.port, get_info=ldap3.ALL, tls=ldapTls)

        if self.credentials.doKerberos:
            ldapConn = ldap3.Connection(ldapServer)
            ldapConn = self.kerberosAuthentication(ldapConn)
        elif self.credentials.doSimpleBind:
            ldapConn = ldap3.Connection(ldapServer, user=user, password=self.credentials.getAuthenticationSecret(), authentication=ldap3.SIMPLE)
            ldapConn.bind()
        else:
            ldapConn = ldap3.Connection(ldapServer, user=user, password=self.credentials.getAuthenticationSecret(), authentication=ldap3.NTLM)
            try:
                ldapConn.bind()
            except ldap3.core.exceptions.LDAPSocketReceiveError:
                self.logger.error("Can't connect using NTLM, try with -simple-bind option")
                exit(1)

        if ldapConn.result["description"] == "invalidCredentials":
            self.logger.error("Invalid credentials !")
            exit(1)

        return ldapConn

    def __tryLDAPS(self, proto: tls._SSLMethod, port: int) -> int:
        port = port or 636

        ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=proto, ciphers="ALL:@SECLEVEL=0")
        ldapServer = ldap3.Server(self.target.remote, use_ssl=True, port=port, get_info=ldap3.ALL, tls=ldapTls)
        ldapConn = ldap3.Connection(ldapServer)

        try:
            ldapConn.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return None, None
        except ldap3.core.exceptions.LDAPSocketReceiveError:
            pass

        return port, True

    def __tryLDAP(self, port: int) -> int:
        self.logger.debug("LDAPS failed, trying with LDAP.")
        port = port or 389

        ldapServer = ldap3.Server(self.target.remote, use_ssl=False, port=port, get_info=ldap3.ALL)
        ldapConn = ldap3.Connection(ldapServer)

        try:
            ldapConn.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return None
        except ldap3.core.exceptions.LDAPSocketReceiveError:
            return port

        return port

    def kerberosAuthentication(self, ldapConn: ldap3.Connection) -> None:
        blob = Kerberos.kerberosLogin(self.target.remote, self.credentials.username, self.credentials.password,
                                    self.credentials.domain, self.credentials.ntlmhash, self.credentials.aesKey,
                                    kdcHost=self.target.remote)

        request = ldap3.operation.bind.bind_operation(ldapConn.version, ldap3.SASL, self.credentials.username, None, "GSS-SPNEGO", blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        # try to open connection if closed
        if ldapConn.closed:
            ldapConn.open(read_server_info=False)

        ldapConn.sasl_in_progress = True
        response = ldapConn.post_send_single_response(ldapConn.send('bindRequest', request, None))

        ldapConn.sasl_in_progress = False

        if response[0]['result'] != 0:
            raise Exception(response)

        ldapConn.bound = True

        return ldapConn
    
    def search(self, dn: str, filter: str, scope: str, attributes: list = ["*"], cookie: str | bytes | None = None) -> list:
        entries = list()

        ldapConn = self.__Authentication()
        ldapConn.search(
            search_base=dn,
            search_filter=filter,
            search_scope=scope,
            attributes=attributes,
            # Controls to get nTSecurityDescriptor from standard user
            # OWNER_SECURITY_INFORMATION + GROUP_SECURITY_INFORMATION + DACL_SECURITY_INFORMATION
            controls=[("1.2.840.113556.1.4.801", True, "%c%c%c%c%c" % (48, 3, 2, 1, 7), )],
            paged_size=5000,
            paged_cookie=cookie
        )
        entries.extend(ldapConn.response)

        if ldapConn.result.get("controls", False):
            cookie = ldapConn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        else:
            cookie = None

        if cookie:
            entries.extend(self.search(dn, filter, scope, attributes, cookie))

        return entries

    def __createArrayOfObject(self, response: list, obj: object) -> list:

        array = list()

        for entry in response:
            # Not a response object
            if entry["type"] != "searchResEntry":
                continue

            array.append(
                obj(**entry["raw_attributes"])
            )

        return array

    def getNamingContexts(self) -> list:
        response = self.search(
            "",
            "(objectClass=*)",
            ldap3.BASE,
            ["namingContexts"]
        )

        self.namingContexts = response[0]["attributes"]["namingContexts"]
        self.defaultNamingContext = self.namingContexts[0]
        self.configurationNamingContext = self.namingContexts[1]
        self.schemaNamingContext = self.namingContexts[2]
        self.domainDnsZonesNamingContext = self.namingContexts[3]
        self.forestDnsZonesNamingContext = self.namingContexts[4]

    def getAllUsers(self) -> List[ADUser]:
        if len(self.users):
            return self.users
        self.logger.print("Retrive all users")

        response = self.search(
            self.defaultNamingContext,
            "(sAMAccountType=%d)" % (sAMAccountType.SAM_NORMAL_USER_ACCOUNT),
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "userPrincipalName", "sAMAccountName", "objectSid", "ntSecurityDescriptor", "userAccountControl", "memberOf"]
        )

        self.users = self.__createArrayOfObject(response, ADUser)

        return self.users

    def getAllGroups(self) -> List[ADGroup]:
        if len(self.groups):
            return self.groups
        self.logger.print("Retrive all groups")

        response = self.search(
            self.defaultNamingContext,
            "(|(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d)(sAMAccountType=%d))" % (
                sAMAccountType.SAM_GROUP_OBJECT,
                sAMAccountType.SAM_NON_SECURITY_GROUP_OBJECT,
                sAMAccountType.SAM_ALIAS_OBJECT,
                sAMAccountType.SAM_NON_SECURITY_ALIAS_OBJECT
            ),
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "sAMAccountName", "objectSid", "ntSecurityDescriptor", "memberOf"]
        )

        self.groups = self.__createArrayOfObject(response, ADGroup)
        
        return self.groups
    
    def getAllComputers(self) -> List[ADComputer]:
        if len(self.computers):
            return self.computers
        self.logger.print("Retrive all computers")

        response = self.search(
            self.defaultNamingContext,
            "(sAMAccountType=%d)" % (sAMAccountType.SAM_MACHINE_ACCOUNT),
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "sAMAccountName", "objectSid", "ntSecurityDescriptor", "userAccountControl", "memberOf"]
        )

        self.computers = self.__createArrayOfObject(response, ADComputer)

        return self.computers
    
    def getAllCertificatesTemplates(self) -> List[ADCertificateTemplate]:
        if len(self.certificatesTemplates):
            return self.certificatesTemplates
        self.logger.print("Retrive all certificateTemplates")

        response = self.search(
            f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.configurationNamingContext}",
            "(objectClass=pkiCertificateTemplate)",
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "ntSecurityDescriptor"]
        )

        self.certificatesTemplates = self.__createArrayOfObject(response, ADCertificateTemplate)

        return self.certificatesTemplates
    
    def getAllGPOs(self) -> List[ADGPO]:
        if len(self.gpos):
            return self.gpos
        self.logger.print("Retrive all GPOs")

        response = self.search(
            f"CN=Policies,CN=System,{self.defaultNamingContext}",
            "(objectClass=groupPolicyContainer)",
            ldap3.SUBTREE,
            ["DistinguishedName", "displayName", "gPCFileSysPath", "ntSecurityDescriptor"]
        )

        self.gpos = self.__createArrayOfObject(response, ADGPO)

        return self.gpos

    def getAllOUs(self) -> List[ADOU]:
        if len(self.ous):
            return self.ous
        self.logger.print("Retrive all OUs")

        response = self.search(
            self.defaultNamingContext,
            "(objectClass=organizationalUnit)",
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "ntSecurityDescriptor"]
        )

        self.ous = self.__createArrayOfObject(response, ADOU)

        return self.ous
    
    def getAllContainers(self) -> List[ADContainer]:
        if len(self.containers):
            return self.containers
        self.logger.print("Retrive all containers")

        response = self.search(
            self.defaultNamingContext,
            "(objectClass=container)",
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "nTSecurityDescriptor"]
        )

        self.containers.extend(self.__createArrayOfObject(response, ADContainer))

        response = self.search(
            self.configurationNamingContext,
            "(objectClass=container)",
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "nTSecurityDescriptor"]
        )

        self.containers.extend(self.__createArrayOfObject(response, ADContainer))

        return self.containers

    def getAdminSDHolder(self) -> List[ADAdminSDHolder]:
        if len(self.adminSDHolder):
            return self.adminSDHolder
        self.logger.print("Retrive adminSDHolder")

        response = self.search(
            f"CN=AdminSDHolder,CN=System,{self.defaultNamingContext}",
            "(cn=AdminSDHolder)",
            ldap3.BASE,
            ["DistinguishedName", "name", "ntSecurityDescriptor"]
        )

        self.adminSDHolder = self.__createArrayOfObject(response, ADAdminSDHolder)

        return self.adminSDHolder

    def getSchema(self) -> List[ADSchema]:
        if len(self.schema):
            return self.schema
        self.logger.print("Retrive Schema")

        # Subtree in case it's not inherant
        response = self.search(
            f"CN=Schema,{self.configurationNamingContext}",
            "(objectClass=*)",
            ldap3.SUBTREE,
            ["DistinguishedName", "name", "ntSecurityDescriptor"]
        )

        self.schema = self.__createArrayOfObject(response, ADSchema)

        return self.schema

    def getAllgMSAs(self) -> List[ADgMSA]:
        if len(self.gMSA):
            return self.gMSA
        self.logger.print("Retrive all gMSAs")
        
        response = self.search(
            self.defaultNamingContext,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            ldap3.SUBTREE,
            ["DistinguishedName", "sAMAccountName", "objectSid", "ntSecurityDescriptor", "memberOf"]
        )

        self.gMSA = self.__createArrayOfObject(response, ADgMSA)

        return self.gMSA

    def getDomain(self) -> ADDomain:
        if self.domain:
            return self.domain
        self.logger.print("Retrive domain")

        response = self.search(
            self.defaultNamingContext,
            "(objectClass=*)",
            ldap3.BASE,
            ["DistinguishedName", "objectSid", "ntSecurityDescriptor"]
        )

        self.domain: ADDomain = self.__createArrayOfObject(response, ADDomain)[0]

        return self.domain

    def gatherAllInformations(self) -> None:
        self.getAllUsers()
        self.getAllGroups()
        self.getAllComputers()
        self.getAllCertificatesTemplates()
        self.getAllGPOs()
        self.getAllOUs()
        self.getAllgMSAs()
        self.getAdminSDHolder()
        self.getSchema()
        self.getDomain()

    def isPrincipalExists(self, principal: str) -> ADObject | None:
        if principal.startswith("S-1-"):
            principalObject = ADGroup.getGroupFromSid(self.groups, principal) or ADUser.getUserFromSid(self.users, principal) or ADComputer.getComputerFromSid(self.computers, principal) or ADgMSA.getgMSAFromSid(self.gMSA, principal)
        else:
            principalObject = ADGroup.getGroupSid(self.groups, principal) or ADUser.getUserSid(self.users, principal) or ADComputer.getComputerSid(self.computers, principal) or ADgMSA.getgMSASid(self.gMSA, principal)

        return principalObject

    def getImplicitGroups(self, principalObject: ADObject) -> List[ADGroup]:
         # Detect computers or users
        if isinstance(principalObject, (ADUser, ADgMSA, )):
            # Users: Domains User, Everyone, Authenticated Users
            return [
                ADGroup(
                    [WELL_KNOWN_SID.DOMAIN_USERS.name.encode()],
                    [WELL_KNOWN_SID.DOMAIN_USERS.name.encode()],
                    [WELL_KNOWN_SID.DOMAIN_USERS.name.encode()],
                    "".join([self.domain.objectSid, WELL_KNOWN_SID.DOMAIN_USERS.value]),
                    None,
                    []
                ),
                ADGroup(
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    WELL_KNOWN_SID.EVERYONE.value,
                    None,
                    []
                ),
                ADGroup(
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    WELL_KNOWN_SID.AUTHENTICATED_USER.value,
                    None,
                    []
                )
            ]
        elif isinstance(principalObject, ADComputer):
            # Computers: Domains Computers, Everyone, Authenticated Users
            return [
                ADGroup(
                    [WELL_KNOWN_SID.DOMAIN_COMPUTERS.name.encode()],
                    [WELL_KNOWN_SID.DOMAIN_COMPUTERS.name.encode()],
                    [WELL_KNOWN_SID.DOMAIN_COMPUTERS.name.encode()],
                    "".join([self.domain.objectSid, WELL_KNOWN_SID.DOMAIN_COMPUTERS.value]),
                    None,
                    []
                ),
                ADGroup(
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    [WELL_KNOWN_SID.EVERYONE.name.encode()],
                    WELL_KNOWN_SID.EVERYONE.value,
                    None,
                    []
                ),
                ADGroup(
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    [WELL_KNOWN_SID.AUTHENTICATED_USER.name.encode()],
                    WELL_KNOWN_SID.AUTHENTICATED_USER.value,
                    None,
                    []
                )
            ]

    def getMemberOfForPrincipal(self, principalObject: ADObject) -> List[ADObject]:        
        return principalObject.memberOf

    def getGroupRecursive(self, group: str) -> List[ADGroup]:
        groups: List[ADGroup] = list()

        groupObject: ADGroup = ADGroup.getGroupSidFromDistinguishedName(self.groups, group)

        if groupObject is None:
            self.logger.debug(f"Can't find group {group}")
            return groups
        
        groups.append(groupObject)

        if len(groupObject.memberOf):
            for group in groupObject.memberOf:
                groups.extend(self.getGroupRecursive(group))

        return groups

    def getGroupsOfPrincipal(self, principalObject: ADObject) -> set[ADGroup]:
        groups = set()

        memberOf = self.getMemberOfForPrincipal(principalObject)
        implicitMemberOf = self.getImplicitGroups(principalObject)

        # If the user have no group
        if not len(memberOf):
            return implicitMemberOf

        for group in memberOf:
            groups.update(self.getGroupRecursive(group))

        if len(implicitMemberOf):
            groups.update(implicitMemberOf)

        return groups

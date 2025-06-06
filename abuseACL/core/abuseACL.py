
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE
from impacket.uuid import bin_to_string

from abuseACL.structures.structures import ACCESS_MASK, RIGHTS_GUID
from abuseACL.structures.ADObject.ADComputer import ADComputer
from abuseACL.structures.ADObject.ADGroup import ADGroup
from abuseACL.structures.ADObject.ADUser import ADUser
from abuseACL.structures.ADObject.ADgMSA import ADgMSA
from abuseACL.structures.ADObject import ADObject
from abuseACL.network.LDAP import LDAP
from abuseACL.core.Logger import Logger

class abuseACL:

    def __init__(self, ldap: LDAP, logger: Logger, extends: bool) -> None:
        self.ldap                   = ldap
        self.logger                 = logger
        self.extends                = extends

        self.users                  = self.ldap.getAllUsers()
        self.groups                 = self.ldap.getAllGroups()
        self.computers              = self.ldap.getAllComputers()
        self.certificatesTemplates  = self.ldap.getAllCertificatesTemplates()
        self.gpos                   = self.ldap.getAllGPOs()
        self.ous                    = self.ldap.getAllOUs()
        self.gMSAs                  = self.ldap.getAllgMSAs()

        self.allObjects = self.users + self.groups + self.computers + \
            self.certificatesTemplates + self.gpos + self.ous + self.gMSAs
        
        if self.extends:
            self.adminSDHolder      = self.ldap.getAdminSDHolder()
            self.schema             = self.ldap.getSchema()
            self.domain             = self.ldap.getDomain()
            self.containers         = self.ldap.getAllContainers()

            self.allObjects += self.adminSDHolder + self.schema + [self.domain] + self.containers

    def isObjectTypeGUIDRestricted(self, ace) -> RIGHTS_GUID:
        isDangerous = self.isObjectTypeGUIDDangerous(ace)

        # Restricted but has a dangerous objectTypeGUID
        if isDangerous:
            return isDangerous
        else:
            # Not restricted
            if "ObjectTypeLen" not in ace["Ace"].fields:
                return RIGHTS_GUID.ALL

        return False

    def isObjectTypeGUIDDangerous(self, ace) -> RIGHTS_GUID:
        # Check if the field exists
        if "ObjectTypeLen" in ace["Ace"].fields:
            # Check the length
            if ace["Ace"]["ObjectTypeLen"]:
                objectTypeGUID = bin_to_string(ace["Ace"]["ObjectType"]).lower()

                # Check if the right is dangerous
                for right in RIGHTS_GUID:
                    if right.value == objectTypeGUID:
                        return right

        return False

    def printVuln(self, entry: ADObject, ace, perm: ACCESS_MASK, principal: ADUser|ADComputer|ADgMSA|ADGroup, right: RIGHTS_GUID) -> None:
        self.logger.vuln(f"Result for {entry.sAMAccountName} ({entry.distinguishedName})")
        self.logger.vuln(f"    ACE Type           : {ace['Ace'].__class__.__name__}")
        self.logger.vuln(f"    Access mask        : {perm.name}")
        self.logger.vuln(f"    Principal (SID)    : {principal.sAMAccountName} ({principal.objectSid})")

        if right:
            # Right and GUID
            self.logger.vuln(f"    Object type (GUID) : {right.name} ({right.value})")

    def abuse(self, principal: ADUser|ADComputer|ADgMSA|ADGroup) -> None:
        """
        crossDomain possible check with another forest.
        Check if the user is the owner of another user, group, computer, certificateTemplate, gpo
        Check if the user have dangerous write on another user, (group, Self the user can add itself to the group), computer, certificateTemplate, gpo
        """
        haveVulnerability   = False
        principalSid        = principal.objectSid

        self.logger.debug(f"SID of the principal: {principalSid}")

        for entry in self.allObjects:
            entry: ADObject
            # Name of the Object without AD
            objectName = entry.__class__.__name__[2:]

            securityDescriptor = entry.nTSecurityDescriptor

            # Check securityDescriptor, sometimes, we can't read them like for (Microsoft Exchange container, idk why)
            if securityDescriptor is None:
                continue

            if principalSid == securityDescriptor["OwnerSid"].formatCanonical():
                haveVulnerability = True
                self.logger.vuln(f"{principal.sAMAccountName} is the owner of {entry.sAMAccountName}")

            # ACE in ACL
            for ace in securityDescriptor["Dacl"].aces:

                # Only check ALLOW
                if ace["Ace"].ACE_TYPE in [ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                    # Only check concerned user
                    if principalSid != ace["Ace"]["Sid"].formatCanonical():
                        continue

                    # Don't need to check if already full rights
                    if ace["Ace"]["Mask"].hasPriv(ACCESS_MASK.FULL_CONTROL.value):
                        haveVulnerability = True
                        self.printVuln(entry, ace, ACCESS_MASK.FULL_CONTROL, principal, False)
                        continue

                    for perm in ACCESS_MASK:
                        # Check if permission in current ACE
                        if not (ace["Ace"]["Mask"].hasPriv(perm.value)):
                            continue

                        vuln = f"{principal.sAMAccountName} can do {perm.name} on {entry.sAMAccountName}"
                        right = False

                        # Edit one of the object's attributes. The attribute is referenced by an "ObjectType GUID".
                        if perm.name == ACCESS_MASK.WRITE_PROPERTIES.name:
                            right = self.isObjectTypeGUIDRestricted(ace)
                            if right:
                                vuln = f"{principal.sAMAccountName} can do {perm.name}:{right} on {entry.sAMAccountName}"
                            else:
                                # Debug, in case it is useful, (No vulnerability)
                                self.logger.debug(vuln)
                                vuln = ""

                        # Perform "Extended rights". "AllExtendedRights" refers to that permission being unrestricted. This right can be restricted by specifying the extended right in the "ObjectType GUID".
                        elif perm.name == ACCESS_MASK.ALL_EXTENDED_RIGHTS.name:
                            right = self.isObjectTypeGUIDRestricted(ace)
                            if right:
                                vuln = f"{principal.sAMAccountName} can do {perm.name}:{right} on {entry.sAMAccountName}"
                            else:
                                # Debug, in case it is useful, (No vulnerability)
                                self.logger.debug(vuln)
                                vuln = ""

                        if len(vuln):
                            haveVulnerability = True

                            self.printVuln(entry, ace, perm, principal, right)

        # In case no vulnerability were found for the principal
        if not haveVulnerability:
            self.logger.error(f"Nothing found for principal {principal.sAMAccountName}")


from abuseACL.structures.ADObject import ADObject

class ADDomain(ADObject):

    def __init__(self, distinguishedName: list[bytes], objectSid: list[bytes], nTSecurityDescriptor: list[bytes]) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.objectSid              = self.convertSid(objectSid[0])
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])
        self.sAMAccountName         = self.distinguishedName.replace("DC=", "").replace(",", ".")

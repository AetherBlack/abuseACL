
from abuseACL.structures.ADObject import ADObject

class ADOU(ADObject):

    def __init__(self, distinguishedName: str, name: str, nTSecurityDescriptor: bytes) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])

        self.sAMAccountName = self.name
        self.objectSid = str()

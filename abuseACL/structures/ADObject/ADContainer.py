
from abuseACL.structures.ADObject import ADObject

class ADContainer(ADObject):

    def __init__(self, distinguishedName: list[bytes], name: list[bytes], nTSecurityDescriptor: list[bytes]) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0]) if len(nTSecurityDescriptor) else None

        self.sAMAccountName = self.name
        self.objectSid = str()

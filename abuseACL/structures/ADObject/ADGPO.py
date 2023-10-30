
from abuseACL.structures.ADObject import ADObject

class ADGPO(ADObject):

    def __init__(self, distinguishedName: str, displayName: str, gPCFileSysPath: str, nTSecurityDescriptor: bytes) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.displayName            = displayName[0].decode()
        self.gPCFileSysPath         = gPCFileSysPath[0].decode()
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])

        self.sAMAccountName = self.displayName
        self.objectSid = str()

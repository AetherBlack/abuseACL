
from abuseACL.structures.ADObject import ADObject

class ADGroup(ADObject):

    def __init__(self, distinguishedName: str, name: str, sAMAccountName: str, objectSid: str, nTSecurityDescriptor: bytes) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.sAMAccountName         = sAMAccountName[0].decode().lower()
        self.objectSid              = self.convertSid(objectSid[0])
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])

    @staticmethod
    def getGroupSid(groups: list, groupname: str) -> str:
        for group in groups:
            group: ADGroup

            if group.sAMAccountName == groupname:
                return group.objectSid

        return None

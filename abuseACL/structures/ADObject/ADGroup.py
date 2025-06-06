
from abuseACL.structures.ADObject import ADObject

class ADGroup(ADObject):

    def __init__(self, distinguishedName: list[bytes], name: list[bytes], sAMAccountName: list[bytes], objectSid: list[bytes], nTSecurityDescriptor: list[bytes], memberOf: list[bytes]) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.sAMAccountName         = sAMAccountName[0].decode().lower()
        self.objectSid              = self.convertSid(objectSid[0]) if isinstance(objectSid, list) else objectSid
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0]) if nTSecurityDescriptor else None
        self.memberOf               = [group.decode() for group in memberOf]

    @staticmethod
    def getGroupSid(groups: list, groupname: str) -> str:
        for group in groups:
            group: ADGroup

            if group.sAMAccountName == groupname:
                return group.objectSid

        return None

    @staticmethod
    def getGroupFromSid(groups: list[ADObject], groupSid: str):
        for group in groups:
            group: ADGroup
        
            if group.objectSid == groupSid:
                return group

    @staticmethod
    def getGroupSidFromDistinguishedName(groups: list[ADObject], groupDN: str) -> ADObject:
        for group in groups:
            group: ADGroup

            if group.distinguishedName.lower() == groupDN.lower():
                return group

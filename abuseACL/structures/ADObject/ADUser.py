
from abuseACL.structures.ADObject import ADObject

class ADUser(ADObject):

    def __init__(self, distinguishedName: str, name: str, userPrincipalName: str, sAMAccountName: str, objectSid: str, nTSecurityDescriptor: bytes, userAccountControl: int) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.userPrincipalName      = userPrincipalName[0].decode() if len(userPrincipalName) else userPrincipalName
        self.sAMAccountName         = sAMAccountName[0].decode()
        self.objectSid              = self.convertSid(objectSid[0])
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])
        self.userAccountControl     = int(userAccountControl[0].decode())

        self.isUserEnable           = self.userAccountControl & 0x0002

    @staticmethod
    def getUserSid(users: list, username: str) -> str:
        for user in users:
            user: ADUser

            if user.sAMAccountName == username:
                return user.objectSid

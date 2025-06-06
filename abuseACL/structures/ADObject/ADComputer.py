
from abuseACL.structures.ADObject import ADObject

class ADComputer(ADObject):

    def __init__(self, distinguishedName: str, name: str, sAMAccountName: str, objectSid: str, nTSecurityDescriptor: bytes, userAccountControl: int, memberOf: list[bytes]) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.name                   = name[0].decode()
        self.sAMAccountName         = sAMAccountName[0].decode().lower()
        self.objectSid              = self.convertSid(objectSid[0])
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])
        self.userAccountControl     = int(userAccountControl[0].decode())
        self.memberOf               = [group.decode() for group in memberOf]

        self.isUserEnable = self.userAccountControl & 0x0002

    @staticmethod
    def getComputerSid(computers: list, computername: str) -> str:
        for computer in computers:
            computer: ADComputer

            if computer.sAMAccountName == computername:
                return computer.objectSid

        return None

    @staticmethod
    def getComputerFromSid(computers: list[ADObject], computerSid: str):
        for computer in computers:
            computer: ADComputer

            if computer.objectSid == computerSid:
                return computer

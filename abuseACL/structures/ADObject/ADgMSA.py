
from abuseACL.structures.ADObject import ADObject

class ADgMSA(ADObject):

    def __init__(self, distinguishedName: str, sAMAccountName: str, objectSid: str, nTSecurityDescriptor: bytes, memberOf: list[bytes]) -> None:
        self.distinguishedName      = distinguishedName[0].decode()
        self.sAMAccountName         = sAMAccountName[0].decode().lower()
        self.objectSid              = self.convertSid(objectSid[0])
        self.nTSecurityDescriptor   = self.parseSecurityDescriptor(nTSecurityDescriptor[0])
        self.memberOf               = [group.decode() for group in memberOf]

    @staticmethod
    def getgMSASid(gMSAs: list, principal: str) -> str:
        for gMSA in gMSAs:
            gMSA: ADgMSA

            if gMSA.sAMAccountName == principal:
                return gMSA.objectSid

        return None

    @staticmethod
    def getgMSAFromSid(gMSAs: list[ADObject], gMSASid: str):
        for gMSA in gMSAs:
            gMSA: ADgMSA

            if gMSA.objectSid == gMSASid:
                return gMSA

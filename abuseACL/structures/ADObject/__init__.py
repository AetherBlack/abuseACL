
from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

class ADObject:

    def __init__(self) -> None:
        pass

    def parseSecurityDescriptor(self, nTSecurityDescriptor: bytes) -> SR_SECURITY_DESCRIPTOR:
        return SR_SECURITY_DESCRIPTOR(nTSecurityDescriptor)

    def convertSid(self, objectSid: bytes) -> str:
        return format_sid(objectSid)

    def __str__(self) -> str:
        return "{0: <30} {1}".format(self.sAMAccountName, self.objectSid)

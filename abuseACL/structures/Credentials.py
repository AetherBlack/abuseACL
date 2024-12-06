
class Credentials:

    def __init__(self, username: str, password: str, domain: str, ntlmhash: str, aesKey: str, doKerberos: bool, doSimpleBind: bool) -> None:
        self.username = username
        self.password = password
        self.domain = domain
        self.ntlmhash = ntlmhash
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.doSimpleBind = doSimpleBind

    def getAuthenticationSecret(self) -> str:
        return self.password or self.ntlmhash

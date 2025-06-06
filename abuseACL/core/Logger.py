
from colorama import Style, Fore

import time

class Logger:

    def __init__(self, debug: bool, timestamp: bool) -> None:
        self.__debug = debug
        self.__timestamp = timestamp

    def __toStdout(self, color: str, title: str, msg: str) -> None:
        timestamp = str()

        if self.__timestamp:
            timestamp = time.strftime("[%Y/%m/%d %H:%M:%S] ")

        print("%s%s[%s] %s%s" % (color, timestamp, title, msg, Style.RESET_ALL))

    def debug(self, msg: str) -> None:
        if self.__debug:
            self.__toStdout(Fore.BLUE, "d", msg)

    def error(self, msg: str) -> None:
        self.__toStdout(Fore.RED, "!", msg)

    def vuln(self, msg: str) -> None:
        self.__toStdout(Fore.GREEN, "*", msg)

    def print(self, msg: str) -> None:
        self.__toStdout("", "i", msg)

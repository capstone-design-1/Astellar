from os import walk
import psutil

def getFolderNames(path: str) -> list:
    return next(walk(path), (None, None, []))[1]


def getFileNames(path: str) -> list:
    return next(walk(path), (None, None, []))[2]

def killProxify():
    for proc in psutil.process_iter():
        if proc.name() == "proxify":
            proc.kill()
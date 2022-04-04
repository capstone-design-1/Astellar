from os import walk

def getFolderNames(path: str) -> list:
    return next(walk(path), (None, None, []))[1]


def getFileNames(path: str) -> list:
    return next(walk(path), (None, None, []))[2]
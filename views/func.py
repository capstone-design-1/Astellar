from os import walk
import psutil

def getFolderNames(path: str) -> list:
    """
    인자로 넘어온 경로 안에 존재하는 폴더 목록을 리턴한다.

    getFilderNames('/home') 과 같이 호출을 할 경우, '/home' 경로 안에 들어 있는
    폴더 목록을 추출한다. 이를 list type으로 리턴한다.

    Args:
        path: 폴더 목록을 가져올 경로
    
    Returns:
        list: 폴더 목록을 list type으로 리턴

    """

    return next(walk(path), (None, None, []))[1]


def getFileNames(path: str) -> list:
    """
    인자로 넘어온 경로 안에 존재하는 파일 목록을 리턴한다.

    getFileName('/home') 과 같이 호출을 할 경우, '/home' 경로 안에 들어 있는
    파일 목록을 추출한다. 이를 list type으로 리턴한다.

    Args:
        path: 파일 목록을 가져올 경로
    
    Returns:
        list: 파일 목록을 list type으로 리턴
    """

    return next(walk(path), (None, None, []))[2]

def killProxify():
    """
    현재 host에 동작 중인 프로세스 중에서 proxify 라는 프로세스만 kill 하는 함수 이다.

    현재 host에서 동작 중인 프로세스 목록을 가져오기 위해 psutil 모듈을 사용한다.
    psutil 모듈로 동작 중인 프로세스 목록을 가져와, 이 중에 proxify 프로세스를 검색한다.
    이후 발견한 프로세스를 kill 한다.
    """
    for proc in psutil.process_iter():
        if proc.name() == "proxify":
            proc.kill()

def killChrome():
    """
    현재 host에 동작 중인 프로세스 중에서 chrome 프로세스만 kill 하는 함수 이다.

    현재 host에서 동작 중인 프로세스 목록을 가져오기 위해 psutil 모듈을 사용한다.
    psutil 모듈로 동작 중인 프로세스 목록을 가져와, 이 중에 chrome 프로세스를 검색한다.
    이후 발견한 프로세스를 kill 한다.
    """
    for proc in psutil.process_iter():
        if proc.name() == "chrome":
            proc.kill()
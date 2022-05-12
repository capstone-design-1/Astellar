import time
import os
import re

from views.func import getFileNames
from views.analyze.packet import Packet
from views.analyze.analyze import Analyze
from views.analyze.url_tree import UrlTree

def fileMonitoring(SAVE_DIR_PATH: str, target_site: str, share_memory: dict):
    """
    이 함수는 멀티 프로세싱 동작을 위해 호출되는 함수이며, share_memory 파라미터로 분석 결과를 공유 메모리에 저장한다.
    SAVE_DIR_PATH 파라미터를 기준으로 해당 폴더 안에 새로운 파일이 생성 되었는지를 모니터링한다.

    실행 시점 이후, 초기 파일 목록 개수는 0으로 시작 된다. 이후 무한 반복문으로 SAVE_DIR_PATH 파라미터를
    기준으로 해당 폴더를 3초에 한번 씩 모니터링 한다. 이후 새로운 파일이 생성 되었을 경우, 다음과 같은 동작을
    수행한다.
    1) 새로 추가된 파일 개수를 저장하고 파일 목록을 추출한다. 
    2) 추출된 파일 목록을 하나씩 열어 Packet 객체로 분석한다.
    3) Packet 객체에서 Content-type을 검증하여 분석 하려는 객체만 추출한다.
    4) 위 과정을 통과한 Packet 객체만 Analyze 및 urltree 분석에 사용된다.
    5) 분석 결과는 공유 메모리인 share_memory 파라미터에 저장된다.

    Args:
        - SAVE_DIR_PATH: 모니터링 할 경로
        - target_site: 사용자가 지정한 타겟 호스트, share_memory 파라미터에서 key로 사용
        - share_memory: 멀티 프로세싱 동작을 위해 메인 프로세스와 데이터를 공유하기 위해 사용
    """

    prev_file_list = set()
    prev_file_count = len(prev_file_list)
    analyze_obj = Analyze(target_site)
    url_tree_obj = UrlTree()
    target_folder = SAVE_DIR_PATH + target_site

    while True:
        cur_file_list = set(getFileNames(target_folder))
        
        ## 새로 추가된 파일이 없을 경우
        if prev_file_count == len(cur_file_list):
            time.sleep(3)
            continue

        new_file_name = cur_file_list - prev_file_list
        prev_file_list = cur_file_list
        prev_file_count = len(cur_file_list)
        
        for file_name in new_file_name:

            ## 다른 호스트는 검사하지 않음
            if not target_site in file_name:
                continue

            with open(os.path.join(target_folder, file_name), encoding="utf8", errors='ignore') as data:
                packet_data = data.read()

                ## 요청 데이터만 있고 응답이 없는 경우
                regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)
                if regex_result == None:
                    continue

                ## Content-type 검증
                packet = Packet(packet_data, regex_result, file_name)
                if checkContentType(packet):
                    analyze_obj.start(packet, file_name, target_folder)
                    url_tree_obj.start(f"http://{packet.request['header']['Host']}{packet.request['url']}", file_name, target_site)

        ## 공유 메모리에 분석 결과 저장
        share_memory[target_site] = {
            "wappalyzer" : analyze_obj.wappalyzer_obj.wappalyer_result,
            "attack_vector" : analyze_obj.attack_vector_obj.attack_vector_result,
            "packet_count" : prev_file_count,
            "url_tree" : url_tree_obj.getObjectToDict(target_site)
        }


def checkContentType(packet) -> bool:
    """
    Packet 객체에서 Content-Type 값을 검사하여 filter_content_type_list 변수에 없는 Packet 만 true를 리턴한다.
    filter_content_type_list 변수에 있는 Content-Type은 분석 해봤자, 의미 없는 데이터 이므로 다음과 같이 분류한 것이다.
    만약, Response 데이터에 Content-Type 헤더가 없을 경우, 분석 대상이 된다.

    Args:
        - packet: Packet 객체
    
    Returns:
        - True or False

    """

    ## Reference: https://developer.mozilla.org/ko/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
    filter_content_type_list = [
        "audio/aac",
        "application/x-abiword",
        "video/x-msvideo",
        "application/vnd.amazon.ebook",
        "application/x-bzip",
        "application/x-bzip2",
        "application/x-csh",
        "text/csv",
        "application/msword",
        "application/epub+zip",
        "image/x-icon",
        "image/gif",
        "text/calendar",
        "application/java-archive",
        "image/jpeg",
        "video/mpeg",
        "audio/midi",
        "application/vnd.apple.installer+xml",
        "application/vnd.oasis.opendocument.presentation",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.text",
        "audio/ogg",
        "video/ogg",
        "application/ogg",
        "application/pdf",
        "application/vnd.ms-powerpoint",
        "application/x-rar-compressed",
        "application/rtf",
        "application/x-sh",
        "image/svg+xml",
        "application/x-shockwave-flash",
        "application/x-tar",
        "image/tiff",
        "application/x-font-ttf",
        "application/vnd.visio",
        "audio/x-wav",
        "audio/webm",
        "video/webm",
        "image/webp",
        "application/x-font-woff",
        "application/xhtml+xml",
        "application/vnd.ms-excel",
        "application/xml",
        "application/vnd.mozilla.xul+xml",
        "application/zip",
        "video/3gpp",
        "video/3gpp2",
        "application/x-7z-compressed",
        "video/mp4",
        "application/octer-stream"      # file download 관련
    ]

    ## response header에 Content-Type 키가 없으면, attack_vector 검사 해야 함.
    if not "Content-Type" in packet.response["header"].keys():
        return True

    for content_type in filter_content_type_list:
        ## filter 할 content_type이 있으면, attack_vector 분석 안함.
        if content_type in packet.response["header"]["Content-Type"]:
            return False
    
    return True
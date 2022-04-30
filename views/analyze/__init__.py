import time
import os
import re

from views.func import getFileNames
from views.analyze.packet import Packet
from views.analyze.analyze import Analyze
from views.analyze.url_tree import UrlTree

def fileMonitoring(SAVE_DIR_PATH, target_site, share_memory):
    prev_file_list = set()
    prev_file_count = len(prev_file_list)
    analyze_obj = Analyze(target_site)
    url_tree_obj = UrlTree()
    target_folder = SAVE_DIR_PATH + target_site

    while True:
        cur_file_list = set(getFileNames(target_folder))
        
        if prev_file_count == len(cur_file_list):
            time.sleep(3)
            continue

        # print("new file detect")
        new_file_name = cur_file_list - prev_file_list
        prev_file_list = cur_file_list
        prev_file_count = len(cur_file_list)
        
        # tmp_count = 0
        for file_name in new_file_name:
            # tmp_count += 1
            # print("Log: " + os.path.join(target_folder, file_name))

            ##  다른 호스트는 검사하지 않기
            if not target_site in file_name:
                continue

            with open(os.path.join(target_folder, file_name), encoding="utf8", errors='ignore') as data:
                packet_data = data.read()
                regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

                ##  요청 데이터만 있고 응답이 없는 경우
                if regex_result == None:
                    continue

                packet = Packet(packet_data, regex_result, file_name)
                if checkContentType(packet):
                    analyze_obj.start(packet, file_name, target_folder)
                    url_tree_obj.start(f"http://{packet.request['header']['Host']}{packet.request['url']}", file_name, target_site)

            # if tmp_count % 100 == 0:
            #     share_memory[target_site] = {
            #         "wappalyzer" : analyze_obj.wappalyzer_obj.wappalyer_result,
            #         "attack_vector" : analyze_obj.attack_vector_obj.attack_vector_result,
            #         "packet_count" : prev_file_count
            #     }

        share_memory[target_site] = {
            "wappalyzer" : analyze_obj.wappalyzer_obj.wappalyer_result,
            "attack_vector" : analyze_obj.attack_vector_obj.attack_vector_result,
            "packet_count" : prev_file_count,
            "url_tree" : url_tree_obj.getObjectToDict(target_site)
        }


def checkContentType(packet) -> bool:

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
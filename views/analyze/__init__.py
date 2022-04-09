import time
import os
import re

from views.func import getFileNames
from views.analyze.packet import Packet
from views.analyze.analyze import Analyze


def fileMonitoring(SAVE_DIR_PATH, target_site, share_memory):
    prev_file_list = set()
    prev_file_count = len(prev_file_list)
    analyze_obj = Analyze(target_site)
    target_folder = SAVE_DIR_PATH + target_site


    while True:
        cur_file_list = set(getFileNames(target_folder))

        if prev_file_count == len(cur_file_list):
            continue

        # print("new file detect")
        new_file_name = cur_file_list - prev_file_list
        prev_file_list = cur_file_list
        prev_file_count = len(cur_file_list)

        for file_name in new_file_name:
            # print("Log: " + os.path.join(target_folder, file_name))

            with open(os.path.join(target_folder, file_name), encoding="utf8", errors='ignore') as data:
                packet_data = data.read()
                regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

                ##  요청 데이터만 있고 응답이 없는 경우
                if regex_result == None:
                    continue

                packet = Packet(packet_data, regex_result)
                analyze_obj.start(packet)

        share_memory[target_site] = {
            "wappalyzer" : analyze_obj.wappalyzer_obj.wappalyer_result,
            "packet_count" : prev_file_count
        }

        time.sleep(3)
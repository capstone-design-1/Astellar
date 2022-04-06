import time

from views.func import getFileNames


def fileMonitoring(target_folder):
    prev_file_list = set()

    while True:
        cur_file_list = set(getFileNames(target_folder))

        if len(prev_file_list) == len(cur_file_list):
            continue
        
        new_file_name = cur_file_list - prev_file_list
        prev_file_list = cur_file_list


        time.sleep(3)
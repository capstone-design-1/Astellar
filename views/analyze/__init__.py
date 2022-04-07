import time
import os

from views.func import getFileNames
from views.analyze.packet import Packet


def fileMonitoring(target_folder):
    prev_file_list = set()

    while True:
        cur_file_list = set(getFileNames(target_folder))

        if len(prev_file_list) == len(cur_file_list):
            continue
        print("new file detect")
        new_file_name = cur_file_list - prev_file_list
        prev_file_list = cur_file_list

        for file_name in new_file_name:
            print(os.path.join(target_folder, file_name))
            with open(os.path.join(target_folder, file_name), "rb") as data:
                ## TODO
                ## 이미지 등 파일을 Packet으로 변환할 때 문제 발생
                """
                    Traceback (most recent call last):
                    File "/usr/lib/python3.8/multiprocessing/process.py", line 315, in _bootstrap
                        self.run()
                    File "/usr/lib/python3.8/multiprocessing/process.py", line 108, in run
                        self._target(*self._args, **self._kwargs)
                    File "/home/universe/Desktop/Astellar/views/analyze/__init__.py", line 23, in fileMonitoring
                        packet = Packet(data.read())
                    File "/home/universe/Desktop/Astellar/views/analyze/packet.py", line 6, in __init__
                        self.request = self.__set_request_packet(packet_data.decode('utf-8'))
                    UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 2057: invalid start byte
                """
                packet = Packet(data.read())


        time.sleep(3)
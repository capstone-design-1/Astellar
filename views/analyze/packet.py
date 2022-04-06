import re
import json

class Packet:
    def __init__(self, packet_data: str):
        self.request = self.__set_request_packet(packet_data)
        self.response = self.__set_response_packet(packet_data)
    

    def __set_request_packet(self, packet_data) -> dict:
        regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

        if regex_result == None:
            raise

        return_data = dict()
        index = regex_result.span()[0]

        request_packet = packet_data[:index]
        request_header = request_packet[ : request_packet.find("\n\n")].strip()
        if request_header.startswith("POST") == True:
            return_data["body"] = request_packet[request_packet.find("\n\n") : ].strip()
        else:
            return_data["body"] = ""
        return_data["header"] = dict()
        method_list = ("GET", "POST", "OPTIONS", "DELETE", "PUT", "CONNECT", "HEAD")

        for header in request_header.split("\n"):

            ##  method 및 url 추출
            if header.startswith(method_list) == True:
                tmp = header.split(" ")

                if len(tmp) != 3:
                    raise
                
                return_data["method"] = tmp[0]
                return_data["url"] = tmp[1]
                return_data["http_protocol"] = tmp[2]

            ##  그 외 request header 추출
            else:
                tmp = header.split(": ")
                return_data["header"][tmp[0]] = tmp[1]

        return return_data
    

    def __set_response_packet(self, packet_data) -> dict:
        regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

        if regex_result == None:
            raise
        
        return_data = dict()
        index = regex_result.span()[0]
        response_packet = packet_data[index : ]
        response_header = response_packet[ : response_packet.find("\n\n")].strip()
        return_data["body"] = response_packet[response_packet.find("\n\n") : ].strip()
        return_data["header"] = dict()

        headers = response_header.split("\n")
        if headers[0].startswith("HTTP/") == True:
            return_data["status_code"] = headers[0].split(" ")[1]
        else:
            raise

        ## TODO
        ## 중복된 헤더가 있을 경우는??
        for header in headers[1:]:
            tmp = header.split(": ")
            return_data["header"][tmp[0]] = tmp[1]

        return return_data
    

    def requestToString(self) -> str:
        return json.dumps(self.request)
    
    def responseToString(self) -> str:
        return json.dumps(self.response)
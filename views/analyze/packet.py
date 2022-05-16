from urllib.parse import urlparse

class Packet:
    """
    Packet 파일을 Request 및 Response 패킷으로 구조화하는 객체

    """

    def __init__(self, packet_data: str, regex_result, file_name: str):
        """
        객체가 생성되자마자 인자로 넘어온 packet_data를 Request 및 Response 패킷으로 구조화 시킴.
        
        Args:
            - packet_data:  packet의 row data
            - regex_result: re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)의 정규 표현식 결과, Request 와 Response 경계를 찾기 위한 정규표현식
            - file_name:    현재 분석 중인 파일 이름, this_is_file_name.txt
        
        """

        self.file_name = file_name
        self.target_host = self.__set_target_host()
        self.request = self.__set_request_packet(packet_data, regex_result)
        self.response = self.__set_response_packet(packet_data, regex_result)
    

    def __set_target_host(self) -> str:
        """
        self.file_name의 파일 이름을 통해 현재 호스트 값을 찾아냄.
        ex) casper.or.kr:80-[random_str].txt

        Returns:
            - str: 현재 분석 중인 호스트 값을 리턴함. ex) casper.or.kr:80
        """

        return self.file_name.split("-")[0]


    def __set_request_packet(self, packet_data: str, regex_result) -> dict:
        """
        인자 값인 packet_data와 Resquest 와 Response 경계를 알아내기 위한 정규 표헌식 regex_result로 Request 패킷을 구조화 시킴

        Args:
            - packet_data: packet의 row data
            - regex_result: re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)의 정규 표현식 결과, Request 와 Response 경계를 찾기 위한 정규표현식

        Returns:
            - return_data:  {
                                "method" : "POST",
                                "url" : "/dashboard?idx=1",
                                "http_protocol" : "HTTP/1.1",
                                "header" : {
                                    "Host" : "casper.or.kr:443",    ### or   casper.or.kr
                                    "Cookies" : "test=1; php=asdf; aaaa=bbbb",
                                    "User-Agent" : "asdf",
                                    ...
                                },
                                "body" : "id=admin&pw=admin"
                            }
        """

        return_data = dict()
        index = regex_result.span()[0]

        request_packet = packet_data[:index]
        request_header = request_packet[ : request_packet.find("\n\n")].strip()
        if request_header.startswith("POST") == True:
            return_data["body"] = request_packet[request_packet.find("\n\n") : ].strip()
        else:
            return_data["body"] = ""
        return_data["header"] = dict()
        return_data["header"]["Host"] = self.target_host
        method_list = ("GET", "POST", "OPTIONS", "DELETE", "PUT", "CONNECT", "HEAD")

        for header in request_header.split("\n"):

            ##  method 및 url 추출
            if header.startswith(method_list) == True:
                tmp = header.split(" ")

                if len(tmp) != 3:
                    raise
                
                url_parse = urlparse(tmp[1])
                if len(url_parse.path) == 0:
                    return_data["url"] = "/"
                else:
                    return_data["url"] = url_parse.path
                
                if len(url_parse.query) != 0:
                    return_data["url"] += "?" + url_parse.query
                if len(url_parse.fragment) != 0:
                    return_data["url"] += "?" + url_parse.fragment

                return_data["method"] = tmp[0]
                return_data["http_protocol"] = tmp[2]

            ##  그 외 request header 추출
            else:
                if len(header) == 0:
                    continue
                tmp = header.split(": ")

                if len(tmp) == 1:
                    return_data["header"][tmp[0]] = ""
                elif len(tmp) == 2:
                    return_data["header"][tmp[0]] = tmp[1]
                else:
                    continue

        return return_data
    

    def __set_response_packet(self, packet_data: str, regex_result) -> dict:
        """
        인자 값인 packet_data와 Resquest 와 Response 경계를 알아내기 위한 정규 표헌식 regex_result로 Response 패킷을 구조화 시킴

        Args:
            - packet_data: packet의 row data
            - regex_result: re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)의 정규 표현식 결과, Request 와 Response 경계를 찾기 위한 정규표현식

        Returns:
            - return_data:  {
                                "http_protocol" : "HTTP/1.1",
                                "status_code" : 200,
                                "reason" : "OK",   // ("Not Found", "Forbidden")
                                "header" : {
                                    "Set-Cookie" : "asdf=asdf",
                                    "Server" : "apache"
                                    ...
                                },
                                "body" : "<html><head><title>test</title></head><body>This is sample data ...."
                            } 
        """

        return_data = dict()
        index = regex_result.span()[0]
        response_packet = packet_data[index : ]
        response_header = response_packet[ : response_packet.find("\n\n")].strip()
        return_data["body"] = response_packet[response_packet.find("\n\n") : ].strip()
        return_data["header"] = dict()

        headers = response_header.split("\n")
        if headers[0].startswith("HTTP/") == True:
            tmp = headers[0].split(" ")

            if len(tmp) < 3:
                raise

            return_data["http_protocol"] = tmp[0]
            return_data["status_code"] = tmp[1]
            return_data["reason"] = " ".join(tmp[2:])
            
        else:
            raise

        ## TODO
        ## 중복된 헤더가 있을 경우는??
        for header in headers[1:]:
            if len(header) == 0:
                continue
            tmp = header.split(": ")
            
            if len(tmp) == 1:
                    return_data["header"][tmp[0]] = ""
            elif len(tmp) == 2:
                return_data["header"][tmp[0]] = tmp[1]
            else:
                continue

        return return_data
    

    def getRequestToRawData(self) -> str:
        """
        구조화 된 Request 데이터를 Row 데이터로 만들어 리턴.

        """

        return_raw = f"{self.request['method']} {self.request['url']} {self.request['http_protocol']}\r\n"

        for header in self.request["header"]:
            return_raw += f"{header}: {self.request['header'][header]}\r\n"
        
        if self.request["method"] == "POST":
            return_raw += f"\r\n{self.request['body']}"
        else:
            return_raw += f"\r\n"
        
        return return_raw
    
    def getResponseToRawData(self) -> str:
        """
        구조화 된 Response 데이터를 Row 데이터로 만들어 리턴.

        """
        
        return_raw = f"{self.response['http_protocol']} {self.response['status_code']} {self.response['reason']}"

        for header in self.response["header"]:
            return_raw += f"{header}: {self.response['header'][header]}\r\n"
        
        return_raw += f"\r\n{self.response['body']}"

        return return_raw
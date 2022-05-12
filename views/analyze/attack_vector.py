from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
import re
import datetime
import os
import socket, ssl
import json


class AttackVector:
    """
    Packet 객체를 통해 request 및 response 패킷을 분석 후 attack vector를 제공
    """

    def __init__(self):
        """
        Members:
            - attack_vector_result: 분석 결과를 저장
            - idor_url_check:       IDOR 가능 여부를 확인한 URL 목록, IDOR 가능 여부를 확인하기 전에 해당 변수를 통해 테스트 할지를 결정
            - file_name:            현재 분석하고 있는 Packet 객체의 파일 이름
            - target_host:          file_name 으로 부터 host 값을 추출함
            - target_port:          file_name 으로 부터 port 값을 추출함
        """

        self.attack_vector_result = list()
        self.idor_url_check = list()
        self.file_name = ''
        self.target_host = ''
        self.target_port = ''
        

    def start(self, packet, file_name: str, target_folder: str):
        """
        Attack vector 분석을 시작하는 함수.
        Packet 객체를 기준으로 SQLI, IDOR, S3 Bucket 등 Attack Vector 를 분석하는 함수를 호출함.
        self.start(Packet, 'this_is_file_name.txt', '/tmp/data/casper.or.kr/')

        Args:
            - packet:        Packet 객체
            - file_name:     분석하고 있는 Packet 객체의 파일 이름
            - target_folder: 분석하고 있는 폴더
        
        Members:
            - file_name:    분석하고 있는 Packet 객체의 파일 이름
            - file_path:    분석하고 있는 Packet 객체의 파일의 절대 경로, ex) /tmp/data/casper.or.kr/this_is_file_name.txt
            - packet:       Packet 객체
        """

        self.file_name = file_name
        self.file_path = os.path.join(target_folder, file_name)
        self.packet = packet

        self.__set_target()
        self.__detect_SQLI()
        self.__detect_CORS()
        self.__detect_reflectXSS()
        self.__detect_SSRF()
        self.__detect_open_redirect()
        self.__detect_KeyLeak()
        self.__detect_S3_bucket()
        self.__detect_IDOR()
        self.__detect_file_download()
        self.__detect_DOM_XSS()
        self.__detect_JWT()
        self.__detect_file_upload_tag()
        self.__detect_file_upload()


    def __set_target(self):
        """
        file_name 값으로 host와 port 정보를 추출함.
        """

        host_info = self.file_name.split("-")[0]
        tmp = host_info.split(":")

        if len(tmp) == 1:
            self.target_host = "http://" + tmp[0]
            self.target_port = 80
        elif tmp[1] == "443":
            self.target_host = "https://" + tmp[0]
            self.target_port = 443
        else:
            self.target_host = host_info
            self.target_port = tmp[1]


    def __detect_reflectXSS(self):
        #response 예외처리하기 -> html ?
        try:
            soup = BeautifulSoup(self.packet.response["body"], 'html.parser')
        except:
            return
        if soup.find("html") == None :
            return

        input_tag = soup.find_all("input")
        textarea_tag = soup.find_all("textarea")

        if(input_tag == None and textarea_tag == None):
            return
        
        # 정규표현식으로 ? 뒤에 내용 추출 &로 split -> 안됨 ㅠㅠㅠㅠ물음표안됨왜안됨
        
        tmp = self.packet.request["url"].split("?")
        # len(tmp) <= 1 : 파라미터값 없다는 뜻
        if len(tmp) <= 1:
            return

        p = tmp[1].split("&")
        flag = set()
        for parameter in p:
            data = parameter.split("=")
            if len(data) != 2:
                continue
            name, value = data
            for tag in input_tag :
                try:
                    if tag["name"] == name and tag["value"] == value:
                        flag.add(name)
                except:
                    continue

            for tag in textarea_tag:
                try:
                    if tag["name"] == name and tag.text == value:
                        flag.add(name)
                except:
                    continue
        
        if not flag:
            return

        flag = list(flag)

        self.__set_result({
            "detect_name" : "Reflect XSS",
            "method" : self.packet.request["method"],
            "url" : self.target_host + self.packet.request["url"],
            "body" : self.packet.request["body"],
            "vuln_parameter" : flag,
            "risk" : "medium",
            "file_name" : self.file_name,
            "reference" : "",
            "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
            "file_path" : self.file_path
        })


    def __detect_DOM_XSS(self):
        try:
            soup = BeautifulSoup(self.packet.response["body"], 'html.parser')
        except:
            return
        if soup.find("html") == None :
            return

        js_tag = soup.find_all("script")
        comp = re.compile('eval\(')
        res = re.search(comp, str(js_tag))
        if res:
            self.__set_result({
            "detect_name" : "DOM XSS",
            "method" : self.packet.request["method"],
            "url" : self.target_host + self.packet.request["url"],
            "body" : self.packet.request["body"],
            "vuln_parameter" : 'eval()',
            "risk" : "high",
            "file_name" : self.file_name,
            "reference" : "",
            "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
            "file_path" : self.file_path
            })
        return


    def __detect_KeyLeak (self):
        from . import reKey
        flag = []

        strResponse = str(self.packet.response["header"])
        for i in reKey.compKey:
            res = re.search(reKey.compare[i], strResponse)
            if res:
                flag.append(i)

        if not flag:
            return

        self.__set_result({
            "detect_name" : "Key Leak",
            "method" : self.packet.request["method"],
            "url" : self.target_host + self.packet.request["url"],
            "body" : self.packet.request["body"],
            "vuln_parameter" : flag, #keyValue
            "risk" : "info",
            "file_name" : self.file_name,
            "reference" : "",
            "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
            "file_path" : self.file_path
        })
        

    def __detect_SQLI(self):
        """ 
        SQL injection을 탐지하기 위한 함수
        
        """

        if self.packet.request["method"] == "GET":
            params = self.packet.request["url"].split("?")

            if len(params) == 1:
                return
            
            params = params[1]

        elif self.packet.request["method"] == "POST":
            
            if len(self.packet.request["body"]) == 0:
                return
            
            params = self.packet.request["body"]

        else: return


        if "Content-Type" in self.packet.response["header"].keys() and self.packet.response["header"]["Content-Type"].find("application/json") != -1:
            data = params.lower()
            ## TODO
            ## 탐지할 문자열을 list화 해야함.
            if "asc" in data or "desc" in data or "order" in data or "table" in data:
                self.__set_result({
                    "detect_name" : "SQLI",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : self.packet.request["body"],
                    "vuln_parameter" : data[0],
                    "risk" : "high",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })

        else:
            for param in params.split("&"):
                data = param.split("=")

                if len(data) == 2 and (data[1].lower() == "asc" or data[1].lower() == "desc" or "table" in data[0].lower() or data[0].lower().find("order") != -1):
                    self.__set_result({
                        "detect_name" : "SQLI",
                        "method" : self.packet.request["method"],
                        "url" : self.target_host + self.packet.request["url"],
                        "body" : self.packet.request["body"],
                        "vuln_parameter" : data[0],
                        "risk" : "high",
                        "file_name" : self.file_name,
                        "reference" : "",
                        "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                        "file_path" : self.file_path
                    })
    

    def __detect_CORS(self):
        """
        Response 패킷에서 CORS 관련 헤더를 분석.

        """

        filter_content_types = ["css", "font", "otf"]
        if "Content-Type" in self.packet.response["header"].keys():
            for filter_content_type in filter_content_types:
                if filter_content_type in self.packet.response["header"]["Content-Type"].lower():
                    return

        for key in ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"]:
            if key in self.packet.response["header"].keys():
                self.__set_result({
                    "detect_name" : "CORS",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : self.packet.request["body"],
                    "vuln_parameter" : key,
                    "risk" : "info",
                    "file_name" : self.file_name,
                    "reference" : "https://guleum-zone.tistory.com/169",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })
                break
    

    def __detect_SSRF(self):
        """
        Request 및 Response 패킷에서 body 데이터 중 URL 값이 있는지 분석.

        """

        regex = "^(?:http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"

        if self.packet.request["method"] == "GET":
            query = urlparse(self.packet.request["url"]).query

            if len(query) == 0:
                return

        elif self.packet.request["method"] == "POST":
            query = self.packet.request["body"]

        else: return

        for _ in range(5):
            query = unquote(query)

        if "Content-Type" in self.packet.response["header"].keys() and self.packet.response["header"]["Content-Type"].find("application/json") != -1:
            regex_result = re.search(regex, query)
            if regex_result != None:
                self.__set_result({
                    "detect_name" : "SSRF",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : query,
                    "vuln_parameter" : "",
                    "risk" : "high",
                    "file_name" : self.file_name,
                    "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })

        else:
            for q in query.split("&"):
                data = q.split("=")

                if len(data) != 2:
                    return

                regex_result = re.search(regex, data[1])
                if regex_result != None:
                    self.__set_result({
                        "detect_name" : "SSRF",
                        "method" : self.packet.request["method"],
                        "url" : self.target_host + self.packet.request["url"],
                        "body" : "",
                        "vuln_parameter" : data[0],
                        "risk" : "high",
                        "file_name" : self.file_name,
                        "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
                        "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                        "file_path" : self.file_path
                    })


    def __detect_S3_bucket(self):
        """
        AWS에서 제공하고 있는 S3 Bucket 관련 URL이 존재하는지 Request 및 Response 패킷에서 검증
        
        """

        ##  response body 값이 엄청 클 경우(js, css), 해당 파일을 정규 표현식으로 검사하는 과정에서 상당한 시간이 소요됨.
        ##  따라서, js css 파일은 검사하지 않도록 설정
        url_extension = urlparse(self.packet.request["url"]).path.split(".")[::-1][0]

        if url_extension == "js" or url_extension == "css":
            return

        patterns =  [
            "[a-z0-9A-Z.-]+.s3.amazonaws.com",                          #   http://grnhse-marketing-site-assets.s3.amazonaws.com/
            "[a-z0-9A-Z.-]+.s3-[a-z0-9A-Z-].amazonaws.com",
            "[a-z0-9A-Z.-]+.s3-website[.-](us|af|ap|ca|eu|me|sa)",
            "s3.amazonaws.com\/[a-z0-9A-Z._-]+",
            "s3-[a-z0-9A-Z-]+.amazonaws.com\/[a-z0-9A-Z._-]+",
            "s3.(us|af|ap|ca|eu|me|sa)-(east|west|south|southeast|northeast|central|north)-(1|2|3).amazonaws.com\/[a-z0-9A-Z._-]+"    #   https://s3.ap-northeast-2.amazonaws.com/code.coursemos.co.kr/csmsmedia/js/addExtBtn.js
        ]


        for pattern in patterns:
            result = dict()
            req_body_result = re.search(pattern, self.packet.request["body"])
            res_body_result = re.search(pattern, self.packet.response["body"])

            if req_body_result != None:
                result["request"] = self.packet.request["body"][req_body_result.span()[0] : req_body_result.span()[1]]

            if res_body_result != None:
                result["response"] = self.packet.response["body"][res_body_result.span()[0] : res_body_result.span()[1]]
            
            if len(result) != 0:
                if "request" in result.keys():
                    body = self.packet.request["body"]
                else:
                    body = self.packet.response["body"]
                
                self.__set_result({
                    "detect_name" : "S3 Bucket",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : body,
                    "vuln_parameter" : result[list(result.keys())[0]],
                    "risk" : "info",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })


    def __detect_open_redirect(self):
        """
        Request 및 Response 패킷에서 URL 데이터가 있는지 여부를 분석.
        
        """

        ## TODO
        ## 302관련 

        regex = "^(?:http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
        query = urlparse(self.packet.request["url"]).query

        if len(query) == 0:
            return

        for q in query.split("&"):
            data = q.split("=")

            if len(data) != 2:
                return

            regex_result = re.search(regex, unquote(data[1]))
            if regex_result != None:
                self.__set_result({
                    "detect_name" : "Open Redirect",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : "",
                    "vuln_parameter" : data[0],
                    "risk" : "medium",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })


    def __detect_IDOR(self):
        """
        Request 패킷에서 URL의 끝점이 int 로 끝날 경우, IDOR 가능 여부를 테스트.
        
        """
        if self.packet.response["status_code"] != '200':
            return

        url_parse = urlparse(self.packet.request["url"])
        filter_url = ["css", "js", "png", "jpg", "jpeg", "gif", "svg", "scss"]

        for filter in filter_url:
            if url_parse.path.split(".")[::-1][0].lower() == filter:
                return

        ##  파라미터가 있는 경우
        idor_param_list = ["account", "comment", "edit", "email", "id", "no", "user", "Id"]
        if len(url_parse.query) != 0:

            if self.packet.request["method"] == "GET":
                for query in url_parse.query.split("&"):
                    data = query.split("=")

                    for idor_param in idor_param_list:
                        if data[0].lower() in idor_param:
                            self.__set_result({
                                "detect_name" : "IDOR (not req)",
                                "method" : self.packet.request["method"],
                                "url" : self.target_host + self.packet.request["url"],
                                "body" : "",
                                "vuln_parameter" : data[0].lower(),
                                "risk" : "info",
                                "file_name" : self.file_name,
                                "reference" : "",
                                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                                "file_path" : self.file_path
                            })
                    
                    if len(data) == 2:
                        try:
                            int(data[1])
                            self.__set_result({
                                "detect_name" : "IDOR (not req)",
                                "method" : self.packet.request["method"],
                                "url" : self.target_host + self.packet.request["url"],
                                "body" : "",
                                "vuln_parameter" : data[0].lower(),
                                "risk" : "info",
                                "file_name" : self.file_name,
                                "reference" : "",
                                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                                "file_path" : self.file_path
                            })
                        except:
                            pass
                        
        elif self.packet.request["method"] == "POST":
            if not "Content-Type" in self.packet.request["header"].keys():
                return
            
            body = self.packet.request["body"]

            if "application/x-www-form-urlencoded" in self.packet.request["header"]["Content-Type"]:
                for param in body.split("&"):
                    data = param.split("=")[0].lower()

                    for idor_param in idor_param_list:
                        if data in idor_param:
                            self.__set_result({
                                "detect_name" : "IDOR (not req)",
                                "method" : self.packet.request["method"],
                                "url" : self.target_host + self.packet.request["url"],
                                "body" : "",
                                "vuln_parameter" : data,
                                "risk" : "info",
                                "file_name" : self.file_name,
                                "reference" : "",
                                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                                "file_path" : self.file_path
                            })

            elif "application/json" in self.packet.request["header"]["Content-Type"]:
                try:
                    json_data = json.loads(body)
                except:
                    print("[Debug] JSON parse Error: ", self.file_name)
                    return
                
                json_all_keys = list()
                if isinstance(json_data, list):
                    for data in json_data:
                        json_all_keys.extend(self.__get_json_all_keys(data))
                elif isinstance(json_data, dict):
                    json_all_keys = self.__get_json_all_keys(json_data)
                else:
                    return

                for compare in json_all_keys:
                    for idor_param in idor_param_list:
                        if idor_param in compare:
                            self.__set_result({
                                "detect_name" : "IDOR (not req)",
                                "method" : self.packet.request["method"],
                                "url" : self.target_host + self.packet.request["url"],
                                "body" : "",
                                "vuln_parameter" : compare,
                                "risk" : "info",
                                "file_name" : self.file_name,
                                "reference" : "",
                                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                                "file_path" : self.file_path
                            })

            else:
                print("[Debug] Content-Type: ", self.packet.request["header"]["Content-Type"], self.file_name)
                return

        
        ##  파라미터가 없는 경우 
        elif self.packet.request["method"] == "GET":

            ##  /user/123 등의 이러한 url path 형태를 탐지
            regex_url = "\/([\/a-zA-Z0-9%._-])+\/[0-9]+$"
            regex_result = re.search(regex_url, url_parse.path)
            if regex_result == None:
                return
            
            ##  탐지된 url path에서 숫자 위치 찾기
            regex_digit = "\/[\d]+"
            regex_result = re.search(regex_digit, url_parse.path)
            if regex_result == None:
                return
            
            ##  위에서 얻은 정보로 url path에서 숫자만 가져오기
            try:
                match_digit = int(url_parse.path[regex_result.span()[0]+1 : regex_result.span()[1]])
            except ValueError as e:
                print("[Debug] 예외 발생 ", str(e))
                return
            
            ##  IDOR 취약점 테스트를 위해 추출한 숫자 값을 +-1(상황에 따라 다름)
            tmp_digit = []
            if match_digit == 0:
                tmp_digit.append(match_digit + 1)
                tmp_digit.append(match_digit + 2)
            else:
                tmp_digit.append(match_digit + 1)
                tmp_digit.append(match_digit - 1)
            

            ##  IDOR 테스트 요청을 보내기 전에, 검증
            if url_parse.path[ : regex_result.span()[0] + 1] in self.idor_url_check:
                return

            ##  변조된 url path로 요청 보내기
            status_code = []
            self.idor_url_check.append(url_parse.path[ : regex_result.span()[0] + 1])
            for digit in tmp_digit:
                change_path = url_parse.path[ : regex_result.span()[0] + 1] + str(digit) + url_parse.path[regex_result.span()[1] : ]
                raw_request = self.packet.getRequestToRawData().replace(url_parse.path, self.target_host + change_path)

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                parse = urlparse(self.target_host)
                print("[Debug] IDOR sending: " + self.target_host + change_path)
                if parse.scheme == "https":
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=parse.netloc)
                
                sock.connect((parse.netloc, self.target_port))
                sock.sendall(raw_request.encode())

                response = sock.recv(50).decode("utf-8").split("\r\n")[0]
                status_code.append(int(response.split(" ")[1]))

            
            if 200 in status_code:
                self.__set_result({
                    "detect_name" : "IDOR",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : "",
                    "vuln_parameter" : "",
                    "risk" : "medium",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })
    

    def __detect_file_download(self):
        """
        Response 패킷에서 Content-Disposition 헤더를 통해 File Download 여부 분석.
        
        """

        if not "Content-Disposition" in self.packet.response["header"].keys():
            return
        
        if "attachment; filename=" in self.packet.response["header"]["Content-Disposition"]:
            self.__set_result({
                "detect_name" : "File Download",
                "method" : self.packet.request["method"],
                "url" : self.target_host + self.packet.request["url"],
                "body" : "",
                "vuln_parameter" : "",
                "risk" : "medium",
                "file_name" : self.file_name,
                "reference" : "",
                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                "file_path" : self.file_path
            })
    

    def __detect_JWT(self):
        """
        Request 및 Response body 에서 JWT Token이 존재하는지 분석.
        
        """

        url_extension = urlparse(self.packet.request["url"]).path.split(".")[::-1][0]
        filter_extension = ["css", "js", "png", "jpg", "jpeg", "gif", "svg", "scss"]

        if url_extension in filter_extension:
            return

        regex_jwt = "eyJhb[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"

        regex_req_result = re.search(regex_jwt, self.packet.getRequestToRawData())
        if regex_req_result != None:
            self.__set_result({
                "detect_name" : "JSON Web Token",
                "method" : self.packet.request["method"],
                "url" : self.target_host + self.packet.request["url"],
                "body" : "",
                "vuln_parameter" : "",
                "risk" : "info",
                "file_name" : self.file_name,
                "reference" : "",
                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                "file_path" : self.file_path
            })
            return
            
        regex_res_result = re.search(regex_jwt, self.packet.getResponseToRawData())
        if regex_res_result != None:
            self.__set_result({
                "detect_name" : "JSON Web Token",
                "method" : self.packet.request["method"],
                "url" : self.target_host + self.packet.request["url"],
                "body" : "",
                "vuln_parameter" : "",
                "risk" : "info",
                "file_name" : self.file_name,
                "reference" : "",
                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                "file_path" : self.file_path
            })
        
    
    def __detect_file_upload_tag(self):
        """
        Response body 부분에서 file upload 기능이 존재하는지 분석.
        
        """

        if not "Content-Type" in self.packet.response["header"].keys():
            return

        if not "html" in self.packet.response["header"]["Content-Type"]:
            return
        
        try:
            html = BeautifulSoup(self.packet.response["body"], "lxml")
        except Exception as e:
            print("[Debug] file_upload BeautifulSoup error", e)
            return

        if html.find("input", {"type" : "file"}) != None:
            self.__set_result({
                "detect_name" : "File Upload (Tag)",
                "method" : self.packet.request["method"],
                "url" : self.target_host + self.packet.request["url"],
                "body" : "",
                "vuln_parameter" : "",
                "risk" : "info",
                "file_name" : self.file_name,
                "reference" : "",
                "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                "file_path" : self.file_path
            })


    def __detect_file_upload(self):
        """
        Request 패킷 헤더에서 사용자가 파일 업로드를 했을 경우를 탐지
        
        """

        keywords = ["multipart", "form-data", "boundary"]

        if not "Content-Type" in self.packet.request["header"].keys():
            return
        
        for keyword in keywords:
            if keyword in self.packet.request["header"]["Content-Type"]:
                self.__set_result({
                    "detect_name" : "File Upload",
                    "method" : self.packet.request["method"],
                    "url" : self.target_host + self.packet.request["url"],
                    "body" : "",
                    "vuln_parameter" : "",
                    "risk" : "medium",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })
                break


    def __set_result(self, data: dict):
        """
        분석에 의해 탐지된 데이터는 중복 탐지를 제외한 나머지를 맴버 변수인 attack_vector_result 에 저장.

        """

        detect_name = data["detect_name"]
        cur_path = data["url"].split("?")[0]

        ## 분석 결과를 저장하기 전에 탐지 이름, 탐지 경로, 탐지 파라미터가 같은 경우, 중복 탐지이므로 저장하지 않음.
        for result in self.attack_vector_result:

            result_path = result["url"].split("?")[0]
            if detect_name == result["detect_name"] and cur_path == result_path and data["vuln_parameter"] == result["vuln_parameter"]:
                return
        
        self.attack_vector_result.append(data)
    

    def __get_json_all_keys(self, json_data: dict) -> list:
        """
        dict 타입을 가진 데이터에서 모든 key만 추출.
        self.__get_json_all_keys({"key_1" : {"key_2" : "data_2"}})

        Args:
            - json_data: dict 타입 데이터
        
        Returns:
            - list: dict 타입의 모든 key 값을 list 타입으로 리턴.

        """

        return_data = list()

        if not isinstance(json_data, dict):
            return

        for key in json_data.keys():
            if isinstance(json_data[key], dict):
                return_data.append(self.__get_json_all_keys(json_data[key]))
            return_data.append(key)
        
        return return_data


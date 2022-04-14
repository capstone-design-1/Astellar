from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import datetime
import os

class AttackVector:
    def __init__(self):
        self.attack_vector_result = list()
        self.file_name = ''
        self.target_host = ''
        

    def start(self, request: dict, response: dict, file_name: str, target_folder: str):
        self.file_name = file_name
        self.file_path = os.path.join(target_folder, file_name)

        self.__set_target()
        self.__detect_SQLI(request, response)
        self.__detect_CORS(request, response)
        self.__detect_reflectXSS(request, response)
        self.__detect_SSRF(request, response)
        self.__detect_open_redirect(request, response)
        self.__detect_KeyLeak(request, response)
        self.__detect_S3_bucket(request, response)
    

    def __set_target(self):
        host_info = self.file_name.split("-")[0]
        tmp = host_info.split(":")

        if len(tmp) == 1:
            self.target_host = "http://" + tmp[0]
        elif tmp[1] == "443":
            self.target_host = "https://" + tmp[0]
        else:
            self.target_host = host_info


    def __detect_reflectXSS(self, request : dict, response: dict):
        #response 예외처리하기 -> html ?
        try:
            soup = BeautifulSoup(response["body"], 'html.parser')
        except:
            return
        if soup.find("html") == None :
            return

        input_tag = soup.find_all("input")
        textarea_tag = soup.find_all("textarea")

        if(input_tag == None and textarea_tag == None):
            return
        
        # 정규표현식으로 ? 뒤에 내용 추출 &로 split -> 안됨 ㅠㅠㅠㅠ물음표안됨왜안됨
        
        tmp = request["url"].split("?")
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
            "method" : request["method"],
            "url" : self.target_host + request["url"],
            "body" : request["body"],
            "vuln_parameter" : flag,
            "risk" : "high",
            "file_name" : self.file_name,
            "reference" : "",
            "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
            "file_path" : self.file_path
        })

        # high_risk = ["email", "file", "password", "submit", "text", "link", "url", "search"]

        # return_risk = "low"
        # for tag in input_tag:
        #     if tag["type"] in high_risk :
        #         return_risk = "high"
        #         break
        
        # if textarea_tag :
        #     return_risk = "high"

    def __detect_KeyLeak (self, request : dict, response: dict):
        from . import reKey
        flag = []

        strResponse = str(response["header"])
        for i in reKey.compKey:
            res = re.search(reKey.compare[i], strResponse)
            if res:
                flag.append(i)

        if not flag:
            return

        self.__set_result({
            "detect_name" : "Key Leak",
            "method" : request["method"],
            "url" : self.target_host + request["url"],
            "body" : request["body"],
            "vuln_parameter" : flag, #keyValue
            "risk" : "info",
            "file_name" : self.file_name,
            "reference" : "",
            "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
            "file_path" : self.file_path
        })
        

    def __detect_SQLI(self, request: dict, response: dict):
        """ SQL injection을 탐지하기 위한 함수
        
        """

        if request["method"] == "GET":
            params = request["url"].split("?")

            if len(params) == 1:
                return
            
            params = params[1]

        elif request["method"] == "POST":
            
            if len(request["body"]) == 0:
                return
            
            params = request["body"]

        else: return


        if "Content-Type" in response["header"].keys() and response["header"]["Content-Type"].find("application/json") != -1:
            data = params.lower()
            if "asc" in data or "desc" in data or "order" in data:
                self.__set_result({
                    "detect_name" : "SQLI",
                    "method" : request["method"],
                    "url" : self.target_host + request["url"],
                    "body" : request["body"],
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

                if len(data) == 2 and (data[1].lower() == "asc" or data[1].lower() == "desc" or data[0].lower().find("order") != -1):
                    self.__set_result({
                        "detect_name" : "SQLI",
                        "method" : request["method"],
                        "url" : self.target_host + request["url"],
                        "body" : request["body"],
                        "vuln_parameter" : data[0],
                        "risk" : "high",
                        "file_name" : self.file_name,
                        "reference" : "",
                        "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                    })
    

    def __detect_CORS(self, request: dict, response: dict):
        for key in ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"]:
            if key in response["header"].keys():
                self.__set_result({
                    "detect_name" : "CORS",
                    "method" : request["method"],
                    "url" : self.target_host + request["url"],
                    "body" : request["body"],
                    "vuln_parameter" : key,
                    "risk" : "info",
                    "file_name" : self.file_name,
                    "reference" : "https://guleum-zone.tistory.com/169",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })
                break
    

    def __detect_SSRF(self, request: dict, response: dict):
        regex = "^(?:http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"

        if request["method"] == "GET":
            query = urlparse(request["url"]).query

            if len(query) == 0:
                return

        elif request["method"] == "POST":
            query = request["body"]

        else: return


        if "Content-Type" in response["header"].keys() and response["header"]["Content-Type"].find("application/json") != -1:
            regex_result = re.search(regex, query)
            if regex_result != None:
                self.__set_result({
                    "detect_name" : "SSRF",
                    "method" : request["method"],
                    "url" : self.target_host + request["url"],
                    "body" : query,
                    "vuln_parameter" : "",
                    "risk" : "medium",
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
                        "method" : request["method"],
                        "url" : self.target_host + request["url"],
                        "body" : "",
                        "vuln_parameter" : data[0],
                        "risk" : "medium",
                        "file_name" : self.file_name,
                        "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
                        "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                        "file_path" : self.file_path
                    })


    def __detect_S3_bucket(self, request: dict, response: dict):
        patterns =  [
            "[a-z0-9A-Z.-]+.s3.amazonaws.com",                          #   http://grnhse-marketing-site-assets.s3.amazonaws.com/
            "[a-z0-9A-Z.-]+.s3-[a-z0-9A-Z-].amazonaws.com",
            "[a-z0-9A-Z.-]+.s3-website[.-](us|af|ap|ca|eu|me|sa)",
            "s3.amazonaws.com\/[a-z0-9A-Z._-]+",
            "s3-[a-z0-9A-Z-]+.amazonaws.com\/[a-z0-9A-Z._-]+",
            "s3.(us|af|ap|ca|eu|me|sa)-(east|west|south|southeast|northeast|central|north)-(1|2|3).amazonaws.com\/[a-z0-9A-Z._-]+"    #   https://s3.ap-northeast-2.amazonaws.com/code.coursemos.co.kr/csmsmedia/js/addExtBtn.js
        ]

        # TODO
        # 현재 body에 여러개의 s3 bucket이 있을 경우, 첫번째 것만 탐지하게 됨.
        for pattern in patterns:
            result = dict()
            req_body_result = re.search(pattern, request["body"])
            res_body_result = re.search(pattern, response["body"])

            if req_body_result != None:
                result["request"] = request["body"][req_body_result.span()[0] : req_body_result.span()[1]]

            if res_body_result != None:
                result["response"] = response["body"][res_body_result.span()[0] : res_body_result.span()[1]]
            
            if len(result) != 0:
                if "request" in result.keys():
                    body = request["body"]
                else:
                    body = response["body"]
                
                self.__set_result({
                    "detect_name" : "S3 Bucket",
                    "method" : request["method"],
                    "url" : self.target_host + request["url"],
                    "body" : body,
                    "vuln_parameter" : result[list(result.keys())[0]],
                    "risk" : "info",
                    "file_name" : self.file_name,
                    "reference" : "",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })


    def __detect_open_redirect(self, request: dict, response: dict):
        regex = "^(?:http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
        query = urlparse(request["url"]).query

        if len(query) == 0:
            return

        for q in query.split("&"):
            data = q.split("=")

            if len(data) != 2:
                return

            regex_result = re.search(regex, data[1])
            if regex_result != None:
                self.__set_result({
                    "detect_name" : "Open Redirect",
                    "method" : request["method"],
                    "url" : self.target_host + request["url"],
                    "body" : "",
                    "vuln_parameter" : data[0],
                    "risk" : "medium",
                    "file_name" : self.file_name,
                    "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
                    "detect_time" : datetime.datetime.now().strftime('%H:%M:%S'),
                    "file_path" : self.file_path
                })


    def __detect_IDOR(self, request, response):
        # TODO
        # 이미 분석을 하기 전에 packet의 content-type을 검증하기 때문에 필요 없을 것이라고 생각
        # filter_content_type = ["css", "js", "woff"]
        # if "Content-Type" in response["header"].keys():

        #     for content_type in filter_content_type:
        #         if content_type in response["header"]["Content-Type"].lower():
        #             return
        
        # else:
        #     for extension in filter_content_type:
        #         url_extension = request["url"].split("?")[0].split(".")[::-1][0].lower()

        #         if extension == url_extension:
        #             return
        
        url_parse = urlparse(request["url"])

        ##  파라미터가 있는 경우
        if len(url_parse.query) != 0:
            pass
        
        else:
            regex = "\/([\/a-zA-Z._-])+\/[0-9]+"
            regex_result = re.search(regex, url_parse.path)

            if regex_result == None:
                return
            
            



    def __set_result(self, data: dict):
        detect_name = data["detect_name"]
        cur_path = data["url"].split("?")[0]

        for result in self.attack_vector_result:

            result_path = result["url"].split("?")[0]
            if detect_name == result["detect_name"] and cur_path == result_path:
                return
        
        self.attack_vector_result.append(data)
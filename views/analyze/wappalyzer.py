import os
import json
import re

class Wappalyzer:

    def __init__(self, target_site):
        self.asset_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../assets/wappalyzer")
        self.wappalyer_result = dict()
        # self.tmp_tech_result = list()
        self.target_site = target_site
        # self.check_tech = {"dom":0, "headers":0, "js":0, "meta":0, "cookies":0, "website":0}

        self.category = self.__set_category()
        self.technology = self.__set_technology()


    def __set_category(self) -> list:
        with open(os.path.join(self.asset_path, "categories.json")) as json_file:
            json_data = json.load(json_file)
        
        return json_data


    def __set_technology(self) -> dict:
        filenames = "_abcdefghijklmnopqrstuvwxyz"
        return_data = dict()

        for filename in filenames:
            with open(os.path.join(self.asset_path, "{filename}.json".format(filename = filename))) as json_file:
                return_data[filename] = json.load(json_file)
        
        return return_data
    

    def start(self, request: dict, response: dict):

        ##  다른 Host의 header를 검사하는 경우도 있기 때문에,
        ##  request header의 Host와 사용자가 정한 target Host가 같을 때만 detectHeader() 함수 실행
        # if not "Host" in request["header"].keys() or request["header"]["Host"] != self.target_site:
        #     return

        for tech_file_name in self.technology.keys():
            tech_dict = self.technology[tech_file_name]

            for tech in tech_dict.keys():

                ##  이미 탐지한 기술은 검사할 필요 없음
                # if tech in self.tmp_tech_result:
                #     continue

                tech_info = tech_dict[tech]

                for info in tech_info.keys():

                    if info == "dom":
                        continue

                    elif info == "headers" :
                        self.detectHeader(request, response, tech_info[info], tech_info["cats"], tech)

                    elif info == "js":
                        continue

                    elif info == "meta":
                        continue

                    elif info == "cookies":
                        self.detectCookie(request, tech_info[info], tech_info["cats"], tech)

                    elif info == "website":
                        continue
                    
    
    def detectCookie(self, request: dict, tech_info: dict, category: list, info: str):
        """ request 패킷에 cookie 값을 검증하는 함수.

        Args:
            - request:   request 패킷 정보
            - tech_info: cookie 값 검증을 위한 정규 표현식 정보가 들어 있음.
            - category:  해당 분석 정보가 어느 부분인지(backend 언어 인지 frontend 언어 인지 구분을 위한 카테고리) 분류 번호가 들어 있음
            - info:      php 인지 nuxt.js 인지 등을 구분하기 위한 값.
        """
        
        if not "Cookie" in request["header"].keys():
            return

        request_cookie: list = request["header"]["Cookie"].split("; ")

        for tech_cookie in tech_info.keys():
            for cookie in request_cookie:
                if tech_cookie == cookie.split("=")[0]:
                    self.setResult(category, info, request["header"]["Host"])
    

    def detectHeader(self, request: dict, response: dict, tech_info: dict, category: list, info: str):

        for header, pattern in tech_info.items():

            if header in request["header"].keys():
                p = pattern.split("\\;")[0]
                regex_result = re.search(p, request["header"][header], re.I)

                if regex_result != None:
                    self.setResult(category, request["header"][header][regex_result.span()[0] : ], request["header"]["Host"])

            if header in response["header"].keys():
                p = pattern.split("\\;")[0]
                regex_result = re.search(p, response["header"][header].lower(), re.I)
                
                if regex_result != None:
                    self.setResult(category, response["header"][header][regex_result.span()[0] : ], request["header"]["Host"])

    ## TODO
    ## 버전 구하는 기능
    def detectVersion(self, request: dict, response: dict, regex) -> str:
        pass


    def setResult(self, category: list, info: str, target_host: str):
        priority = dict()

        for cat in category:
            priority[str(cat)] = self.category[str(cat)]["priority"]
        
        ##  value를 기준으로 오름차순 정렬
        sorted_dict = sorted(priority.items(), key = lambda item: item[1])
        name = self.category[sorted_dict[0][0]]["name"]
    
        if not target_host in self.wappalyer_result.keys():
            self.wappalyer_result[target_host] = dict()

        if not name in self.wappalyer_result[target_host].keys():
            self.wappalyer_result[target_host][name] = dict()
        
        # if not info in self.tmp_tech_result:
        #     self.tmp_tech_result.append(info)

        data = info.split("/")
        if len(data) > 2:
            print("[!] 예외 상황 발생 ", info)
        
        if not data[0] in self.wappalyer_result[target_host][name].keys():
            self.wappalyer_result[target_host][name][data[0]] = ""

        ##  버전 정보 입력
        if len(data) == 2:
            self.wappalyer_result[target_host][name][data[0]] = data[1]

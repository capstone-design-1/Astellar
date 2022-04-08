import os
import json

class Wappalyzer:

    def __init__(self):
        self.asset_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../assets/wappalyzer")
        self.wappalyer_result = dict()
        self.check_tech = {"dom":0, "headers":0, "js":0, "meta":0, "scriptSrc":0, "html":0, "cookies":0, "website":0}

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

        for tech_file_name in self.technology.keys():
            tech_dict = self.technology[tech_file_name]

            for tech in tech_dict.keys():
                tech_info = tech_dict[tech]

                for info in tech_info.keys():

                    ## NOTICE
                    ## 조건문을 추가하면 self.check_tech 값도 추가해야 함.
                    if info == "dom":
                        continue

                    elif info == "headers":
                        self.detectHeader(request, response, tech_info[info], tech_info["cats"], tech)

                    elif info == "js":
                        continue

                    elif info == "meta":
                        continue

                    elif info == "scriptSrc":
                        continue

                    elif info == "html":
                        continue

                    elif info == "cookies":
                        self.detectCookie(request, response, tech_info[info], tech_info["cats"], tech)

                    elif info == "website":
                        continue

    
    def detectCookie(self, request: dict, response: dict, tech_info: dict, category: list, info: str):
        """ request 패킷에 cookie 값을 검증하는 함수.

        Args:
            - request:   request 패킷 정보
            - response:  response 패킷 정보
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
                    self.setResult(category, info)
    

    def detectHeader(self, request: dict, response: dict, tech_info: dict, category: list, info: str):
        pass


    def setResult(self, category: list, info: str):
        priority = dict()

        for cat in category:
            priority[str(cat)] = self.category[str(cat)]["priority"]
        
        ##  value를 기준으로 오름차순 정렬
        sorted_dict = sorted(priority.items(), key = lambda item: item[1])
        name = self.category[sorted_dict[0][0]]["name"]

        if not name in self.wappalyer_result.keys():
            self.wappalyer_result[name] = list()

        if not info in self.wappalyer_result[name]:
            self.wappalyer_result[name].append(info)

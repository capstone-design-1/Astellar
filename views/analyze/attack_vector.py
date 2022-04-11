from urllib.parse import urlparse
import re

class AttackVector:
    def __init__(self):
        self.attack_vector_result = list()
        self.file_name = ''
        self.target_host = ''
        

    def start(self, request: dict, response: dict, file_name: str):
        self.file_name = file_name

        self.__set_target()
        self.__detect_SQLI(request, response)
        self.__detect_CORS(request, response)
        self.__detect_SSRF(request, response)
        self.__detect_open_redirect(request, response)
    

    def __set_target(self):
        host_info = self.file_name.split("-")[0]
        tmp = host_info.split(":")

        if len(tmp) == 1:
            self.target_host = "http://" + tmp[0]
        elif tmp[1] == "443":
            self.target_host = "https://" + tmp[0]
        else:
            self.target_host = host_info


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
                    "file_name" : self.file_name
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
                        "reference" : ""
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
                    "risk" : "low",
                    "file_name" : self.file_name,
                    "reference" : "https://guleum-zone.tistory.com/169"
                })
                break
    

    def __detect_SSRF(self, request: dict, response: dict):
        regex = "^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"

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
                    "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"
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
                        "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"
                    })


    def __detect_open_redirect(self, request: dict, response: dict):
        regex = "^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
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
                    "reference" : "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"
                })


    def __set_result(self, data: dict):
        # detect_name = data["detect_name"]
        # cur_path = data["url"].split("?")[0]

        # for result in self.attack_vector_result:

        #     result_path = result["url"].split("?")[0]
        #     if detect_name == result["detect_name"] and cur_path == result_path:
        #         return
        
        self.attack_vector_result.append(data)
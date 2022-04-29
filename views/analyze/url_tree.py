from urllib.parse import urlparse

from numpy import isin


class UrlNode:

    def __init__(self, category, path):
        """ 
        
        Member:
            - type: "Folder" 혹은 "File" 둘 중 하나만 가질 수 있음
            - path: "Folder" 일 경우에만 path 변수가 의미 있음
            - packet: "File" 일 경우에만 packet 변수가 의미가 있음. 이는 패킷의 정보가 저장되어 있음.
            - sub_path: "Folder" 일 경우에만 sub_path 변수가 의미가 있음.
        """
        self.type = category
        self.path = path
        self.packet = list()
        self.sub_path = list()
    
    def get_path(self):
        return self.path
    
    def get_sub_path(self):
        return self.sub_path
    
    def set_packet(self, packet_data: dict):
        self.packet.append(packet_data)


class UrlTree:
    
    def __init__(self):
        self.url_tree = dict()
    

    def start(self, url: str, file_name: str):
        """ Url tree 시작

        Args:
            - url: request packet에서 host를 포함한 url, ex) https://naver.com/path?test=1
            - file_name: 현재 packet 파일의 절대 경로, ex) /tmp/data/naver.com/123asdf.txt
        """

        url_parse = urlparse(url)

        if len(url_parse.netloc) == 0 or len(url_parse.path) == 0:
            print("[Debug] Url Tree raise")
            print(url_parse)
            raise
    
        self.__check_host(url_parse.netloc)
        if len(url_parse.query) == 0:
            self.__set_url_tree(url_parse.netloc, url_parse.path, "/", file_name, self.url_tree[url_parse.netloc])
        else:
            self.__set_url_tree(url_parse.netloc, url_parse.path, url_parse.query, file_name, self.url_tree[url_parse.netloc])

    

    def __check_host(self, host: str):
        """ Url tree에 host 존재 여부 확인

        Args:
            - host: packet의 host, ex) naver.com
        
        """

        if not host in self.url_tree.keys():
            self.url_tree[host] = list()
            self.url_tree[host].append(UrlNode("Folder" , "/"))
        
    
    def getObjectToDict(self, host, tree = -1) -> list:
        return_data = list()

        if isinstance(tree, int):
            tree = self.url_tree[host]

        for data in tree:
            return_data.append({
                "type" : data.type,
                "path" : data.get_path(),
                "packet" : data.packet,
                "sub_path" : self.getObjectToDict(host, data.sub_path)
            })
        
        return return_data

    def __set_url_tree(self, host: str, path: str, params: str, file_name: str, url_tree):
        """ Url tree 데이터 넣기

        Args:
            - host: packet의 host, ex) naver.com
            - path: request packet의 path, ex) /path/to/etc
            - params: request packet의 params, ex) id=admin&password=admin
            - file_name: 현재 packet 파일의 절대 경로, ex) /tmp/data/naver.com/123asdf.txt
            - url_tree: 재귀 함수 형태 이므로, url_tree 를 구성하기 위한 파라미터
        """

        path_split = path.split("/")

        if len(path) == 1 or len(path) == 0:
            """
                / 이거 하나만 있거나, 재귀 이후 / 이것 마저 없을 경우 (login.php)
                file 로 구분 됨.
            """

            if isinstance(url_tree, list):
                url_tree[0].set_packet({
                    "file_name" : file_name,
                    "params" : params
                })
            else:
                url_tree.set_packet({
                    "file_name" : file_name,
                    "params" : params
                })

        else:
            if not isinstance(url_tree, list):
                url_tree = url_tree.get_sub_path()

            check = 1
            for i in range(len(url_tree)):
                if path_split[1] == url_tree[i].get_path():
                    self.__set_url_tree(host, "/"+"/".join(path_split[2:]), params, file_name, url_tree[i])
                    check = 0
                    break
            
            if check == 1:
                url_tree.append(UrlNode("Folder", path_split[1]))
                self.__set_url_tree(host, "/"+"/".join(path_split[2:]), params, file_name, url_tree[len(url_tree) - 1])

                
if __name__ == "__main__":
    url_tree = UrlTree()
    url_test = [
        {
            "url" : "http://test.com/",
            "file_name" : "/tmp/data/1"
        },
        {
            "url" : "http://test.com/",
            "file_name" : "/tmp/data/2"
        },
        {
            "url" : "http://test.com/login?id=test&pw=asdf",
            "file_name" : "/tmp/data/3"
        },
        {
            "url" : "http://test.com/login/logout",
            "file_name" : "/tmp/data/4"
        }
    ]

    for data in url_test:
        url_tree.start(data["url"], data["file_name"])
    print(url_tree.getObjectToDict("test.com"))
import os
import shodan
import socket
from urllib.parse import urlparse
import requests


class Osint:
    """
    OSINT 정보를 가져오는 class

    """

    def __init__(self):
        pass


    def start(self, target: str):
        """
        OSINT 정보 검색 시작.
        self.start('casper.or.kr')

        Args:
            - target: 사용자가 지정한 타겟 호스트

        """

        self.target = target

        return {
            "ports" : self.__get_port(),
            "admin_page" : self.__get_admin_page(),
            "indexing" : self.__get_directory_indexing(),
            "logs" : self.__get_log_file(),
            "git" : self.__get_git_folder(),
            "proc" : self.__get_proc_file(),
            "ftp" : self.__get_ftp(),
            "env" : self.__get_env(),
            "ssh" : self.__get_ssh()
        }


    def __get_port(self) -> list:
        """
        Shodan API를 이용하여 열린 port 목록을 가져옴.

        Returns:
            - results: 열린 port 목록을 list 타입으로 리턴.

        """

        try:
            SHODAN_API_KEY = os.environ["SHODAN_API"]
        except:
            return list()

        try:
            domain_to_ip = socket.gethostbyname(self.target)
            
            ##  IP 값인지 확인
            socket.inet_aton(domain_to_ip)
        except:
            return list()
        

        api = shodan.Shodan(SHODAN_API_KEY)
        try:
            results = api.host(domain_to_ip)
        except:
            # shodan.exception.APIError: No information available for that IP.
            return list()

        if not "ports" in results.keys():
            return list()

        return results["ports"]
    

    def __get_directory_indexing(self) -> list:
        """
        Google 검색 엔진을 이용하여 directory indexing URL을 찾아 줌.

        Returns:
            - list: 찾은 directory indexing URL 목록을 list 타입으로 리턴.

        """

        search_payload = f'site:{self.target} intitle:index.of "parent directory"'
        return self.__request(search_payload)


    def __get_admin_page(self) -> list:
        """
        Google 검색 엔진을 이용하여 admin page URL을 찾아 줌.

        Returns:
            - list: 찾은 admin page URL 목록을 list 타입으로 리턴.

        """

        search_payload = f'site:{self.target} intitle:admin.login'
        return self.__request(search_payload)
    

    def __get_log_file(self) -> list:
        """
        Google 검색 엔진을 이용하여 Log file URL을 찾아 줌.

        Returns:
            - list: 찾은 Log file URL 목록을 list 타입으로 리턴.

        """

        search_payload = f'site:{self.target} allintext:username filetype:log'
        return self.__request(search_payload)

    
    def __get_proc_file(self) -> list:
        """
        Google 검색 엔진을 이용하여 proc file URL을 찾아 줌.

        Returns:
            - list: 찾은 proc file URL 목록을 list 타입으로 리턴.

        """
        
        search_payload = f'site:{self.target} inurl:/proc/self/cwd'
        return self.__request(search_payload)
    

    def __get_ftp(self) -> list:
        """
        Google 검색 엔진을 이용하여 노출된 ftp log 및 정보 URL을 찾아 줌.

        Returns:
            - list: 찾은 ftp log 및 정보 URL 목록을 list 타입으로 리턴.

        """
        
        search_payload = f'site:{self.target} intitle:"index of" inurl:ftp'
        return self.__request(search_payload)


    def __get_env(self) -> list:
        """
        Google 검색 엔진을 이용하여 노출된 env 파일의 URL을 찾아 줌.

        Returns:
            - list: 찾은 env 파일의 URL 목록을 list 타입으로 리턴.

        """

        search_payload = f'site:{self.target} DB_USERNAME filetype:env'
        return self.__request(search_payload)
    

    def __get_ssh(self) -> list:
        """
        Google 검색 엔진을 이용하여 노출된 ssh key 파일의 URL을 찾아 줌.

        Returns:
            - list: 찾은 ssh key 파일의 URL 목록을 list 타입으로 리턴.

        """
        
        search_payload = f'site:{self.target} filetype:log username putty'
        return self.__request(search_payload)


    def __get_git_folder(self) -> list:
        """
        Google 검색 엔진을 이용하여 노출된 .git 폴더의 URL을 찾아 줌.

        Returns:
            - list: 찾은 .git 폴더의 URL 목록을 list 타입으로 리턴.

        """
        
        search_payload = f'site:{self.target} intitle:"index of" .git'
        return self.__request(search_payload)


    def __request(self, search_payload: str) -> list:
        """
        Google 검색 엔진에 실제로 요청을 보내어 결과를 리턴함.

        Args: 
            - search_payload: 검색할 payload, ex) site:casper.or.kr intitle:"index of" .git
        
        Returns:
            - return_data: 검색 결과를 list 타입으로 리턴.
        
        """
        
        res = requests.get(f"https://customsearch.googleapis.com/customsearch/v1?cx=0168b3b2caf55756b&key=AIzaSyCxpZEwNoYXUqyyg7ggWvRi4GqLAnQoViw&q={search_payload}")

        return_data = list()
        if res.status_code != 200:
            return
        
        try:
            data = res.json()["items"]
            for d in data:
                if "link" in d.keys():
                    return_data.append(d["link"])
        
            return return_data
        except Exception as e:
            print("[Debug] Directory Indexing Error", e)
            return return_data
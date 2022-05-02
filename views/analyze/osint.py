import os
import shodan
import socket
from urllib.parse import urlparse
import requests


class Osint:

    def __init__(self):
        pass


    def start(self, target):
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
        search_payload = f'site:{self.target} intitle:index.of "parent directory"'
        return self.__request(search_payload)


    def __get_admin_page(self) -> list:
        search_payload = f'site:{self.target} intitle:admin.login'
        return self.__request(search_payload)
    

    def __get_log_file(self) -> list:
        search_payload = f'site:{self.target} allintext:username filetype:log'
        return self.__request(search_payload)

    
    def __get_proc_file(self) -> list:
        search_payload = f'site:{self.target} inurl:/proc/self/cwd'
        return self.__request(search_payload)
    

    def __get_ftp(self) -> list:
        search_payload = f'site:{self.target} intitle:"index of" inurl:ftp'
        return self.__request(search_payload)


    def __get_env(self) -> list:
        search_payload = f'site:{self.target} DB_USERNAME filetype:env'
        return self.__request(search_payload)
    

    def __get_ssh(self) -> list:
        search_payload = f'site:{self.target} filetype:log username putty'
        return self.__request(search_payload)


    def __get_git_folder(self) -> list:
        search_payload = f'site:{self.target} intitle:"index of" .git'
        return self.__request(search_payload)


    def __request(self, search_payload):
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
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from collections import deque
from selenium.webdriver.common.alert import Alert
from urllib.parse import urlparse
from collections import defaultdict


class autoBot:
    
    def __init__(self):
        self.target = ""
        self.queue = deque()
        self.visited = defaultdict(list)
        self.file_extension = ("pdf", "jpeg", "jpg", "png", "hwp", "gif", "doc")

        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('ignore-certificate-errors')
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument("--single-process")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("lang=ko_KR")

        self.driver = webdriver.Chrome(ChromeDriverManager().install(), chrome_options=chrome_options)
        self.driver.implicitly_wait(3)

    def connect_proxy():

        PROXY = "localhost:8888"

        webdriver.DesiredCapabilities.CHROME['proxy'] = {
            "httpProxy": PROXY,
            "ftpProxy": PROXY,
            "sslProxy": PROXY,
            "proxyType": "MANUAL"
        }

    def connect_webdriver(self, site):

        self.driver.get(site)

        before_url = urlparse(self.driver.current_url)
        self.target = before_url.netloc
        print("target : ", self.target)

        self.queue.append([before_url.scheme + "://" + self.target,0])
        self.visited[self.target].append(self.target)


    # href 찾고, 중복인지 검사 -> 중복 ㄴㄴ면 queue에 담기
    def search(self, url, depth):
        self.driver.get(url)
        print("current url : ", self.driver.current_url)
        try:
            alert = Alert(self.driver)
            alert.accept()
        except:
            pass
        
        tmp = self.driver.find_elements_by_tag_name("a")
        for link in tmp:
            next_url = link.get_attribute("href")
            # <a> 태그에서 href 못찾으면 NoneType -> catch
            if not next_url:
                continue
            # url뒤에 #이 있는 경우 별 의미 없는듯 해서 중복으로 간주함 (삭제)
            current_url = urlparse(next_url)
            next_url = f"{current_url.scheme}://{current_url.netloc}{current_url.path}"
            insert_url = next_url+"?"+current_url.query if current_url.query else next_url
            # 동일 path에 다른 parmetar 체크
            if len(self.visited[next_url]) >= 5 or (insert_url in self.visited[next_url]):
                print("no insert this url : "+insert_url)
                continue

            if(current_url.netloc == self.target) and (not current_url.path.endswith(self.file_extension)):
                print("insert : "+insert_url)
                self.queue.append([insert_url, depth+1])
                self.visited[next_url].append(insert_url)

    def BFS(self):
        cnt = 0
        while self.queue :
            url, depth = self.queue.popleft()
            if depth > 1:
                continue
            self.search(url, depth)
        return

    # for link in tmp:
    # 	BFS(link)
    # driver.quit()


#test_code
if __name__ == "__main__":
    test = autoBot()
    test.connect_webdriver("https://changwon.ac.kr")
    test.BFS()
    driver.quit()

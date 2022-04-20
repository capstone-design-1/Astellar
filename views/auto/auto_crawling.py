from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from collections import deque
from selenium.webdriver.common.keys import Keys

'''
PROXY = "localhost:8888"

webdriver.DesiredCapabilities.CHROME['proxy'] = {
    "httpProxy": PROXY,
    "ftpProxy": PROXY,
    "sslProxy": PROXY,
    "proxyType": "MANUAL"
}
'''
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('ignore-certificate-errors')
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument("--single-process")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("lang=ko_KR")

driver = webdriver.Chrome(ChromeDriverManager().install(), chrome_options=chrome_options)
driver.implicitly_wait(3)
driver.get("https://changwon.ac.kr")

tmp = driver.current_url.split("/")
target = tmp[0]+"//"+tmp[2]
print("target : ",target)

queue = deque()
queue.append([target,0])
visited = set()
visited.add(target)

file_extension = ("pdf", "jpeg", "jpg", "png", "hwp", "gif", "doc")

# href 찾고, 중복인지 검사 -> 중복 ㄴㄴ면 queue에 담기
def search(url, depth):
    driver.get(url)
    # alert 예외처리,, 됐나,, 안됐음 ㅠㅠ
    try:
        alert = driver.switch_to_alert()
        alert.accept()
        return
    except:
        pass

    print("current url : ", driver.current_url)
    tmp = driver.find_elements_by_tag_name("a")
    for link in tmp:
        next_url = link.get_attribute("href")
        # <a> 태그에서 href 못찾으면 NoneType -> catch
        if not next_url:
            continue
        # url뒤에 #이 있는 경우 별 의미 없는듯 해서 중복으로 간주함 (삭제)
        idx = next_url.find('#')
        next_url = next_url[:idx]

        # 중복 체크 set search -> O(1)
        if next_url in visited:
            continue
        else:
            # target으로 시작하는지 (다른 도메인 아닌지 check)
            if(next_url.startswith(target)) and (not next_url.endswith(file_extension)):
                queue.append([next_url, depth+1])
                visited.add(next_url)

def BFS():
    global queue
    cnt = 0
    while queue :
        url, depth = queue.popleft()
        if depth > 2:
            continue
        search(url, depth)
    return

BFS()
driver.quit()





# for link in tmp:
# 	BFS(link)
# driver.quit()


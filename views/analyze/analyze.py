from views.analyze.wappalyzer import Wappalyzer
from views.analyze.attack_vector import AttackVector

class Analyze:
    """
    wappalyzer 와 attack_vector 객체를 가지고 있는 class
    """

    def __init__(self, target_site: str):
        """

        Args:
            - target_site: 사용자가 지정한 타겟 호스트, 데이터를 구분하기 위해 key로도 사용됨.

        """
        self.wappalyzer_obj = Wappalyzer(target_site)
        self.attack_vector_obj = AttackVector()
    
    def start(self, packet_data, file_name: str, target_folder: str):
        """
        wappalyzer 와 attack_vector 객체를 통해 분석을 시작 시키는 함수
        self.start(packet: Packet, 'packet_file_name.txt', '/tmp/data/casper.or.kr/')

        Args:
            - packet_data: Packet 객체
            - file_name: 분석하려는 패킷 파일 이름
            - target_folder: 현재 모니터링 하고 있는 폴더
        """
        self.wappalyzer_obj.start(packet_data.request, packet_data.response)
        self.attack_vector_obj.start(packet_data, file_name, target_folder)
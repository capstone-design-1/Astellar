

from views.analyze.wappalyzer import Wappalyzer
from views.analyze.attack_vector import AttackVector



class Analyze:

    def __init__(self):
        self.wappalyzer_obj = Wappalyzer()
        self.attack_vector_obj = AttackVector()
    
    def start(self, packet_data):
        ## TODO
        ## 이미지, 바이너리 파일, 폰트 등등 필터링 해야함.
        self.wappalyzer_obj.start(packet_data.request, packet_data.response)
        self.attack_vector_obj.start(packet_data.request, packet_data.response)
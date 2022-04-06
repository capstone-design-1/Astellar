import os
import json

class Wappalyzer:

    def __init__(self, logs: list):
        self.logs = logs
        self.asset_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../assets/wappalyzer")
        self.category = self.__set_category()
        self.technology = self.__set_technology()
    
    def __del__(self):
        pass
    
    def __start(self):
    
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
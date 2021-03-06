from flask import Blueprint, render_template, current_app, abort, request
import multiprocessing
import re
import time
import requests
import json
import os
import subprocess


from __init__ import socketio
from views.func import getFolderNames
from views.analyze import fileMonitoring
from views.analyze.packet import Packet
from views.func import killProxify, killChrome
from views.analyze.url_tree import UrlTree
from views.auto.auto_crawling import autoBot

bp = Blueprint("detail", __name__, url_prefix = "/detail")

check = dict()
auto_check = dict()
multi_manager = multiprocessing.Manager()
share_memory = multi_manager.dict()
auto_bot_finish_check = multi_manager.dict()

@bp.route("/<target_name>", methods=["GET"])
def detail(target_name):

    if target_name.find("..") != -1 or target_name.find("/") != -1:
        abort(403, description = "Forbidden")

    ##  Check target site
    folder_names = getFolderNames(current_app.config["SAVE_DIR_PATH"])
    if not target_name in folder_names:
        abort(400, description = "Can't find target site.")
    
    return render_template("detail.html", return_data = {
        "target_name" : target_name,
        "monitor_path" : current_app.config["SAVE_DIR_PATH"],
        "dir_name" : folder_names
    })


@socketio.on('message')
def handle_message(data):
    global check
    global share_memory
    
    target = data["target"]
    SAVE_DIR_PATH = data["monitor_path"]

    if target.find("..") != -1:
        socketio.emit("receive", {
            "data" : {
                "error" : "Illegal value."
            }
        }, room = request.sid)
        return

    if not target in getFolderNames(SAVE_DIR_PATH):
        socketio.emit("receive", {
            "data" : {
                "error" : "Not found target."
            }
        }, room = request.sid)
        return
    
    ##  새로운 타겟의 분석 요청이 들어 왔을 때
    if not target in check.keys():
        print(">>>> ", request.sid)
        share_memory[target] = dict()

        result = multiprocessing.Process(name="file_monitoring", target=fileMonitoring, args=(SAVE_DIR_PATH, target, share_memory, ))
        result.start()
        check[target] = dict()
        check[target]["sid"] = list()
        check[target]["sid"].append(request.sid)
        check[target]["process"] = result

    ##  타겟이 분석 중 이지만, 다른 세션으로 접속하였을 때, (똑같은 URL을 여러개 띄웠을 때)
    elif not request.sid in check[target]["sid"]:
        check[target]["sid"].append(request.sid)

    else:
        socketio.emit("receive", {
            "data" : {
                "error" : "Already start analyzing."
            }
        }, room = request.sid)

@socketio.on("disconnect")
def disconnect():
    global check
    global auto_check

    loop_tmp = 0
    for target in check.keys():
        for sid in check[target]["sid"]:
            if sid == request.sid:
                print("[Debug] Client Disconnect")
                check[target]["sid"].remove(sid)
                loop_tmp = 1
                break
        
        if loop_tmp:
            if len(check[target]["sid"]) == 0:
                print("[Debug] Proxify terminate")
                killProxify()
                check[target]["process"].terminate()
                check.pop(target)
            break
    
    loop_tmp = 0
    for target in auto_check.keys():
        for sid in auto_check[target]["sid"]:
            if sid == request.sid:
                print("[Debug] Client Disconnect")
                auto_check[target]["sid"].remove(sid)
                
                print("[Debug] Auto Bot terminate")
                killChrome()
                auto_check[target]["process"].terminate()
                auto_check.pop(target)
                auto_bot_finish_check.pop(target)
                loop_tmp = 1
                break
        
        if loop_tmp == 1:
            break

@socketio.on("get_realtime_data")
def getResultRealTime(data):
    global share_memory

    if data["target"] in share_memory.keys():

        while True:
            try:
                socketio.emit("receive", { 
                    "target" : data["target"],
                    "data" : {
                        "wappalyzer" : share_memory[data["target"]]["wappalyzer"],
                        "attack_vector" : share_memory[data["target"]]["attack_vector"],
                        "packet_count" : share_memory[data["target"]]["packet_count"]
                    }
                }, room = request.sid)
            except:
                socketio.emit("receive", { 
                    "target" : data["target"],
                    "data" : {
                        "packet_count" : 0
                    }
                }, room = request.sid)

            time.sleep(2)

@socketio.on("get_packet_detail")
def getPacketDetail(data):
    global share_memory

    if data["target"] in share_memory.keys():
        file_path = data["file_path"]
        file_name = data["file_name"]
        detect_name = data["detect_name"]

        ##  Security Check
        if file_path.find("..") != -1 or file_name.find("..") != -1:
            return
        if file_path.split("/")[::-1][0] != file_name:
            return
        

        with open(file_path, encoding="utf8", errors='ignore') as file_data:
            packet_data = file_data.read()
            regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

            ##  요청 데이터만 있고 응답이 없는 경우
            if regex_result == None:
                return

            packet = Packet(packet_data, regex_result, file_name)

        with open("./assets/detail.json") as file_data:
            json_data = json.load(file_data)

            if detect_name in json_data.keys():
                socketio.emit("receive", {
                    "target" : data["target"],
                    "data" : {
                        "modal" : {
                            "request" : packet.request,
                            "response" : packet.response,
                            "detail" : json_data[detect_name],
                            "reflect_data" : data["reflect_data"]
                        }
                    }
                }, room = request.sid)


@socketio.on("get_cve")
def getCve(data):
    global share_memory
    cve_result = dict()

    if not data["target"] in share_memory.keys():
        return
    
    CVE_API_KEY = "06c7445b-86a5-4777-bcb3-2398f6163c46"
    api_url = "https://services.nvd.nist.gov/rest/json/cpes/1.0/"

    if not "wappalyzer" in share_memory[data["target"]].keys():
        return
        
    wappalyzer = share_memory[data["target"]]["wappalyzer"]

    for target in wappalyzer.keys():
        for detect_name in wappalyzer[target]["CPE"].keys():
            cpe = wappalyzer[target]["CPE"][detect_name][0]
            version = wappalyzer[target]["CPE"][detect_name][1]

            if cpe == "":
                continue
            if detect_name in cve_result.keys():
                continue

            param = {
                "apiKey" : CVE_API_KEY,
                "cpeMatchString" : cpe,
                "addOns" : "cves",
                "resultsPerPage" : "1"
            }

            try:
                res = requests.get(api_url, params = param, timeout=2).json()
                if len(version) == 0:
                    cve_result[f'{detect_name}'] = res["result"]["cpes"][0]["vulnerabilities"][::-1]
                else:
                    cve_result[f'{detect_name} / {version}'] = res["result"]["cpes"][0]["vulnerabilities"][::-1]
            except:
                continue
    
    if len(cve_result) != 0:
        socketio.emit("receive", {
            "data" : {
                "cve_modal" : {
                    "cve" : cve_result
                }
            }
        }, room = request.sid)


@socketio.on("get_url_tree")
def get_url_tree(data):
    if not data["target"] in share_memory.keys():
        return

    if "url_tree" in share_memory[data["target"]].keys():
        socketio.emit("receive", {
            "data" : {
                "url_tree" : share_memory[data["target"]]["url_tree"]
            }
        }, room = request.sid)

    else:
        socketio.emit("receive", {
            "data" : {
                "url_tree" : {}
            }
        }, room = request.sid)


@socketio.on("get_packet")
def getPacket(data):
    global share_memory

    if data["target"] in share_memory.keys():
        file_path = data["file_path"]
        file_name = data["file_name"]

        with open(os.path.join(file_path, data["target"], file_name), encoding="utf8", errors='ignore') as file_data:
            packet_data = file_data.read()
            regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

            ##  요청 데이터만 있고 응답이 없는 경우
            if regex_result == None:
                return

            packet = Packet(packet_data, regex_result, file_name)

            socketio.emit("receive", {
                "target" : data["target"],
                "data" : {
                    "packet" : {
                        "request" : packet.request,
                        "response" : packet.response,
                    }
                }
            }, room = request.sid)


@socketio.on("search_packet")
def searchPacket(data):
    global share_memory
    url_tree_obj = UrlTree()

    if data["target"] in share_memory.keys():
        result = subprocess.run(["grep", "-rno", data["data"], os.path.join(data["target_path"], data["target"])], capture_output=True).stdout.decode()
        
        result = result.split("\n")
        file_list = list()
        for d in result:
            tmp = d.split(".txt:")

            if len(tmp) != 2:
                continue
            if tmp[0] + ".txt" in file_list:
                continue

            file_list.append(tmp[0] + ".txt")
        
        for file_path in file_list:
            with open(file_path, encoding="utf8", errors='ignore') as file_data:
                packet_data = file_data.read()
                regex_result = re.search("HTTP\/[0,1,2]{1}.[0,1]{1} \d{3} ", packet_data)

                ##  요청 데이터만 있고 응답이 없는 경우
                if regex_result == None:
                    return

                packet = Packet(packet_data, regex_result, file_path.split("/")[::-1][0])
                url_tree_obj.start(f"http://{packet.request['header']['Host']}{packet.request['url']}", file_path.split("/")[::-1][0], data["target"])
        

        socketio.emit("receive", {
            "data" : {
                "url_tree" : url_tree_obj.getObjectToDict(data["target"])
            }
        }, room = request.sid)


@socketio.on("auto")
def autoBotStart(data):
    global share_memory
    global auto_check
    global auto_bot_finish_check

    target = data["target"]

    if not target in share_memory.keys():
        return
    
    ##  새로운 타겟의 분석 요청 및 auto bot이 동작 하고 있지 않을 경우
    if len(auto_check.keys()) == 0 and target not in auto_check.keys():
        auto_bot_finish_check[target] = False
        print(">>>> ", request.sid)
        result = multiprocessing.Process(name="auto_bot", target=autoBotExecute, args=(f"http://{target}", target, auto_bot_finish_check))
        result.start()
        auto_check[target] = dict()
        auto_check[target]["sid"] = list()
        auto_check[target]["sid"].append(request.sid)
        auto_check[target]["process"] = result
        socketio.emit("receive", {
            "data" : {
                "success" : "auto bot을 활성화 합니다."
            }
        }, room = request.sid)
    else:
        socketio.emit("receive", {
            "data" : {
                "error" : "이미 auto bot이 동작 중 입니다."
            }
        }, room = request.sid)


@socketio.on("auto_stop")
def autoBotStop(data):
    global auto_check
    global auto_bot_finish_check

    target = data["target"]

    loop_tmp = 0
    for target in auto_check.keys():
        for sid in auto_check[target]["sid"]:
            if sid == request.sid:
                print("[Debug] Client Disconnect")
                auto_check[target]["sid"].remove(sid)
                
                print("[Debug] Auto Bot terminate")
                killChrome()
                auto_check[target]["process"].terminate()
                auto_check.pop(target)
                auto_bot_finish_check.pop(target)
                loop_tmp = 1

                socketio.emit("receive", {
                    "data" : {
                        "success" : "auto bot이 중지 되었습니다."
                    }
                }, room = request.sid)

                break
        
        if loop_tmp == 1:
            break


@socketio.on("auto_check_finish")
def autoCheckFinish(data):
    global auto_bot_finish_check

    target = data["target"]

    if not target in auto_bot_finish_check.keys():
        return
    
    if auto_bot_finish_check[target] == True:
        auto_check[target]["process"].terminate()
        auto_check.pop(target)
        socketio.emit("receive", {
            "data" : {
                "auto_finish_check" : True
            }
        }, room = request.sid)
    
    else:
        socketio.emit("receive", {
            "data" : {
                "auto_finish_check" : False
            }
        }, room = request.sid)


def autoBotExecute(data, target, auto_bot_finish_check):
    auto_bot_finish_check[target] = False

    auto_bot = autoBot()
    auto_bot_finish_check[target] = auto_bot.start(data)
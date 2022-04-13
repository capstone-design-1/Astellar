from flask import Blueprint, render_template, current_app, abort, request
import multiprocessing
import re
import time


from __init__ import socketio
from views.func import getFolderNames
from views.analyze import fileMonitoring
from views.analyze.packet import Packet

bp = Blueprint("detail", __name__, url_prefix = "/detail")

check = dict()
alive_response = list()
multi_manager = multiprocessing.Manager()
share_memory = multi_manager.dict()

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
        socketio.emit("error", "Illegal value.")
        return

    if not target in getFolderNames(SAVE_DIR_PATH):
        socketio.emit("error", "Not found target.")
        return
    
    ##  새로운 타겟의 분석 요청이 들어 왔을 때
    if not target in check.keys():
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
        socketio.emit("error", "Already start analyzing.")

@socketio.on("disconnect")
def disconnect():
    global check
    global alive_response

    loop_tmp = 0
    for target in check.keys():
        for sid in check[target]["sid"]:
            if sid == request.sid:
                check[target]["sid"].remove(sid)
                loop_tmp = 1
                break
        
        if loop_tmp:
            if len(check[target]["sid"]) == 0:
                check[target]["process"].terminate()
                check.pop(target)
            break

@socketio.on("get_realtime_data")
def getResultRealTime(data):
    global share_memory

    if data["target"] in share_memory.keys():

        while True:
            socketio.emit("receive", { 
                "target" : data["target"],
                "data" : share_memory[data["target"]]
            }, room = request.sid)
            
            time.sleep(3)

@socketio.on("get_packet_detail")
def getPacketDetail(data):
    global share_memory

    if data["target"] in share_memory.keys():
        file_path = data["file_path"]
        file_name = data["file_name"]

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

            packet = Packet(packet_data, regex_result)


        socketio.emit("receive", {
            "target" : data["target"],
            "data" : {
                "modal" : {
                    "request" : packet.request,
                    "response" : packet.response
                }
            }
        }, room = request.sid)
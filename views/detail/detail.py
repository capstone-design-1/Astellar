from multiprocessing import shared_memory
from attr import mutable
from flask import Blueprint, render_template, current_app, abort
import multiprocessing
import time

from __init__ import socketio
from views.func import getFileNames, getFolderNames
from views.analyze import fileMonitoring

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
        "monitor_path" : current_app.config["SAVE_DIR_PATH"]
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
    
    if not target in check.keys():
        share_memory[target] = dict()

        result = multiprocessing.Process(name="file_monitoring", target=fileMonitoring, args=(SAVE_DIR_PATH, target, share_memory, ))
        result.start()
        check[target] = result

        # print(share_memory)

    else:
        print("[Debug] Already start analyzing.")
        socketio.emit("error", "Already start analyzing.")

@socketio.on("disconnect")
def disconnect():
    global check
    global alive_response

    ## TODO 
    ## 특정 타켓 멀티프로세싱만 중지 시켜야함.
    ## 현재는 모든 타겟의 멀티프로세싱을 중지 시키고 있음.
    socketio.emit("alive-check")

    # while 1:
    #     print(">> alive_response: " , alive_response)
    #     time.sleep(2)
    key_list = check.keys()

    for key in key_list:
        print("[Disconnect] " + key)
        check[key].terminate()

@socketio.on("alive-response")
def aliveResponse(data):
    global check
    global alive_response

    if not data["target"] in alive_response:
        alive_response.append(data["target"])

@socketio.on("get_realtime_data")
def getResultRealTime(data):
    global share_memory

    if data["target"] in share_memory.keys():
        socketio.emit("receive", { 
                                    "data" : share_memory[data["target"]]
                                })

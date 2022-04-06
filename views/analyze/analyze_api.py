from flask import Blueprint, abort, jsonify, request, current_app
import os

from views.func import getFolderNames, getFileNames
from views.analyze.packet import Packet


bp = Blueprint("analyze", __name__, url_prefix = "/analyze/api")


@bp.route("/wappalyzer", methods=["GET"])
def wappalyzer():
    
    target = request.args.get("target")
    check_param = checkParameter(target)
    if check_param:
        return check_param
    
    target_folder = current_app.config["SAVE_DIR_PATH"] + target
    log_list = getFileNames(target_folder)

    ## TODO
    ## wappalyzer 기능 동작하는 함수 호출

    return "1"


@bp.route("/packet", methods=["GET"])
def packet():

    target = request.args.get("target")
    check_param = checkParameter(target)
    if check_param:
        return check_param

    target_folder = current_app.config["SAVE_DIR_PATH"] + target
    log_list = getFileNames(target_folder)

    for filename in log_list:
        with open(os.path.join(target_folder, filename)) as data:
            packet = Packet(data.read())
        break
    
    return "1"


def checkParameter(param):
    if not param:
        return {
            "result" : "error",
            "message" : "target 파라미터가 비어 있습니다."
        }, 400
    
    target_list = getFolderNames(current_app.config["SAVE_DIR_PATH"])

    if not param in target_list:
        return {
            "result" : "error",
            "message" : "{target} 폴더가 존재하지 않습니다.".format(target = param)
        }, 400

    return False
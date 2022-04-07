from flask import Blueprint, request, abort, jsonify
import os
import requests
from db.table import *

bp = Blueprint("detail-api", __name__, url_prefix = "/detail/api")

@bp.route("/setSubdomain", methods=["GET"])
def Setsubdomain():
    target = request.args.get("target")
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")

    data = []
    result = []
    os.system('assetfinder '+target+ ' > result.txt')
    f = open("result.txt","r")
    while True:
        line = f.readline()
        if line == '':
            break
        data.append(line.strip())
    
    for i in data:
        url = i
        try:
            res = requests.get("http://"+url, timeout=1)
            result.append({'site' : i, 'status_code' : res.status_code})
        except requests.exceptions.Timeout as e:
            result.append({'site' : i, 'status_code' : "Timeout"})
        except requests.ConnectionError as e2:
            result.append({'site' : i, 'status_code' : "NoResponse"})
        
    f.close()

    subdomain_table = SubdomainTable()
    subdomain_table.insertSubdomain(result, target)

    return {
        "result" : result
    }

@bp.route("/getSubdomain", methods=["GET"])
def getSubdomain():
    target = request.args.get("target")
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")

    subdomain_table = SubdomainTable()
    result = subdomain_table.getSubdomain(target)

    return {
        "result" : result
    }


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

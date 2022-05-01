from flask import Blueprint, jsonify, request, abort, current_app
import os
import requests
import json

from db.table import *
from views.func import getFolderNames
from views.analyze.osint import Osint

bp = Blueprint("detail-api", __name__, url_prefix = "/detail/api")

@bp.route("/subdomain", methods=["GET"])
def Setsubdomain():
    target = request.args.get("target")
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")

    if not target in getFolderNames(current_app.config["SAVE_DIR_PATH"]):
        abort(400, description = f"Not exist {target}")

    data = set()
    result = []
    os.system('./assets/assetfinder '+target+ ' > result.txt')
    f = open("result.txt","r")


    while True:
        line = f.readline()
        if line == '':
            break
        if target not in line:
            continue
        data.add(line.strip())
    
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
    last_search_time = TargetSiteTable().getDomainInfo(target)[0][2]

    return {
        "result" : result,
        "last_search_time" : last_search_time
    }

@bp.route("/getSubdomain", methods=["GET"])
def getSubdomain():
    target = request.args.get("target")
    return_data = list()
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")

    subdomain_table = SubdomainTable()
    result = subdomain_table.getSubdomain(target)
    last_search_time = TargetSiteTable().getDomainInfo(target)[0][2]

    for d in result:
        return_data.append({
            "site" : d[2],
            "status_code" : d[3]
        })

    return {
        "result" : return_data,
        "last_search_time" : last_search_time
    }

@bp.route("/detect_filter", methods=["GET"])
def detectFilter():
    return_data = list()

    with open("./assets/detail.json") as json_data:
        data = json.load(json_data)

    for key in data.keys():
        return_data.append(key)
    
    return jsonify(return_data)


@bp.route("/get_osint", methods=["GET"])
def getOSINT():
    target = request.args.get("target")
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")
    
    osint = Osint()

    return jsonify(osint.start(target))
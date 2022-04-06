from flask import Blueprint, request, abort, jsonify
import os
import requests

bp = Blueprint("detail-api", __name__, url_prefix = "/detail/api")

@bp.route("/subdomain", methods=["GET"])
def subdomain():
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
            result.append({'url' : i, 'status' : str(res)})
        except requests.exceptions.Timeout as e:
            result.append({'url' : i, 'status' : "Timeout"})
        except requests.ConnectionError as e2:
            result.append({'url' : i, 'status' : "NoResponse"})
        

    f.close()

    ## TODO
    ## subdomain 목록 가져오기
    return {
        "result" : result
    }
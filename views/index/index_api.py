from flask import Blueprint, abort, jsonify, request, current_app
import multiprocessing
import re
import os

from db.table import TodoTable
from views.func import getFolderNames
from views.func import killProxify


bp = Blueprint("todo-api", __name__, url_prefix = "/api")
multiprocess = None

@bp.route("/get", methods=["GET"])
def getTodoList():

    return_data = list()
    todo_table = TodoTable()
    todo_data = todo_table.getTodoList()

    for data in todo_data:
        return_data.append({
            "idx" : data[0],
            "context" : data[1],
            "done" : data[2]
        })
        
    return jsonify(return_data)


@bp.route("/add", methods=["POST"])
def insertTodoList():
    if not request.is_json:
        abort(400, description = "Wrong request")

    data = request.get_json()

    if not data or len(data["context"]) == 0:
        return {
            "result" : "error",
            "message" : "내용을 입력해 주세요."
        }
    
    todo_table = TodoTable()
    todo_table.insertContext(data["context"])

    return {
        "result" : "success"
    }


@bp.route("/update", methods=["POST"])
def updateStatus():
    if not request.is_json:
        abort(400, description = "Wrong request")
    
    data = request.get_json()

    try:
        todo_idx = int(data["idx"])
        done = int(data["done"])
    except Exception:
        return {
            "result" : "error",
            "message" : "idx, done 값은 숫자여야 합니다."
        }
    
    todo_table = TodoTable()
    todo_table.updateStatus(todo_idx, done)

    return {
        "result" : "success"
    }


@bp.route("/delete", methods=["POST"])
def deleteContext():
    if not request.is_json:
        abort(400, description = "Wrong request")

    try:
        todo_idx = int(request.get_json()["idx"])
    except Exception:
        return {
            "result" : "error",
            "message" : "idx, done 값은 숫자여야 합니다."
        }
    
    todo_table = TodoTable()
    todo_table.deleteContext(todo_idx)

    return {
        "result" : "success"
    }

@bp.route("/create", methods=["GET"])
def createTarget():
    global multiprocess

    target_name = request.args.get("target")
    save_dir_path = current_app.config["SAVE_DIR_PATH"]

    if target_name == None:
        return {
            "result" : "error",
            "message" : "target 파라미터가 비어 있습니다."
        }, 400
    
    if target_name.find("..") != -1:
        return {
            "result" : "error",
            "message" : ".. 문자열을 사용할 수 없습니다."
        }, 400
    
    if target_name.find("/") != -1:
        return {
            "result" : "error",
            "message" : "/ 문자열을 사용할 수 없습니다."
        }, 400
    
    if target_name in getFolderNames(save_dir_path):
        return {
            "result" : "error",
            "message" : f"{target_name} 폴더가 이미 존재합니다."
        }, 400
    
    regex_result = re.search("[^a-zA-Z0-9.]+", target_name)
    if regex_result != None:
        return {
            "result" : "error",
            "message" : "특수 문자를 사용할 수 없습니다."
        }, 400
    
    try:
        os.makedirs(os.path.join(save_dir_path, target_name))
    except OSError as e:
        return {
            "result" : "error",
            "message" : f"폴더를 생성하는 과정에서 에러가 발생했습니다. {e}"
        }
    
    if not os.access("./assets/proxify", os.X_OK):
        return {
            "result" : "error",
            "message" : "./assets/proxify 파일 실행 권한이 없습니다."
        }

    # if multiprocess != None:
    #     killProxify()
    #     multiprocess.terminate()

    # multiprocess = multiprocessing.Process(name="proxify", target=startProxify, args=(os.path.join(save_dir_path, target_name), ))
    # multiprocess.start()
    
    return {
        "result" : "success",
        "message" : "성공적으로 생성되었습니다"
    }

@bp.route("/start", methods=["GET"])
def initProxify():
    global multiprocess
    
    target_name = request.args.get("target")
    save_dir_path = current_app.config["SAVE_DIR_PATH"]

    if target_name == None:
        return {
            "result" : "error",
            "message" : "target 파라미터가 비어 있습니다."
        }, 400
    
    if target_name.find("..") != -1:
        return {
            "result" : "error",
            "message" : ".. 문자열을 사용할 수 없습니다."
        }, 400
    
    if target_name.find("/") != -1:
        return {
            "result" : "error",
            "message" : "/ 문자열을 사용할 수 없습니다."
        }, 400
    
    if not target_name in getFolderNames(save_dir_path):
        return {
            "result" : "error",
            "message" : f"{target_name} 폴더가 없습니다."
        }, 400
    
    regex_result = re.search("[^a-zA-Z0-9.]+", target_name)
    if regex_result != None:
        return {
            "result" : "error",
            "message" : "특수 문자를 사용할 수 없습니다."
        }, 400
    
    if not os.access("./assets/proxify", os.X_OK):
        return {
            "result" : "error",
            "message" : "./assets/proxify 파일 실행 권한이 없습니다."
        }
    
    if multiprocess != None:
        killProxify()
        multiprocess.terminate()

    multiprocess = multiprocessing.Process(name="proxify", target=startProxify, args=(os.path.join(save_dir_path, target_name), ))
    multiprocess.start()
    
    return {
        "result" : "success"
    }


def startProxify(log_path):
    port = 8888
    os.system(f'./assets/proxify -http-addr "0.0.0.0:{port}" -o {log_path}')
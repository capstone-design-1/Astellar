from flask import Blueprint, render_template, abort, jsonify, request

from db.table import TodoTable


bp = Blueprint("todo-api", __name__, url_prefix = "/todo/api")


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
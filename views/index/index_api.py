from flask import Blueprint, render_template, abort, jsonify

from db.table import *


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

## TODO
## todo 기능 추가
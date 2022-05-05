from flask import Blueprint, render_template, current_app, abort, request

from views.func import getFolderNames


bp = Blueprint("packet", __name__, url_prefix="/packet")

@bp.route("/<target_name>", methods = ["GET"])
def index(target_name):
    if target_name.find("..") != -1 or target_name.find("/") != -1:
        abort(403, description = "Forbidden")

    ##  Check target site
    folder_names = getFolderNames(current_app.config["SAVE_DIR_PATH"])
    if not target_name in folder_names:
        abort(400, description = "Can't find target site.")
    
    return render_template("packet.html", return_data = {
        "target_name" : target_name,
        "monitor_path" : current_app.config["SAVE_DIR_PATH"],
        "dir_name" : folder_names
    })
from flask import Blueprint, render_template, current_app
from views.func import getFileNames, getFolderNames

bp = Blueprint("index", __name__, url_prefix = "/")

@bp.route("/")
def index():
    save_dir_path = current_app.config["SAVE_DIR_PATH"]

    target_data = []
    folder_names = getFolderNames(save_dir_path)

    ##  Get target folder name and file count
    for i, folder_name in enumerate(folder_names):
        target_dir = save_dir_path + folder_name
        target_data.append({})
        target_data[i] = {
            "dir_name" : folder_name,
            "file_count" : len(getFileNames(target_dir))
        }

    return render_template("index.html", target_data=target_data)
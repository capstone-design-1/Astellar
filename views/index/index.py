from flask import Blueprint, render_template, current_app
import favicon

from views.func import getFileNames, getFolderNames
from db.table import *

bp = Blueprint("index", __name__, url_prefix = "/")

@bp.route("/")
def index():
    save_dir_path = current_app.config["SAVE_DIR_PATH"]

    target_data = []
    folder_names = getFolderNames(save_dir_path)
    target_site_table = TargetSiteTable()

    ##  Get target folder name and file count
    for i, folder_name in enumerate(folder_names):
        target_site_table.insertDomain(folder_name)
        
        target_dir = save_dir_path + folder_name
        target_data.append({})

        try:
            favicon_url = favicon.get("http://" + folder_name)[0].url
        except:
            favicon_url = "/images/favicon.png"

        target_data[i] = {
            "dir_name" : folder_name,
            "file_count" : len(getFileNames(target_dir)),
            "favicon_url" : favicon_url
        }



    return render_template("index.html", target_data=target_data)
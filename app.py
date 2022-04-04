from flask import Flask, render_template
from werkzeug.exceptions import HTTPException

from views.login import login
from views.index import index
from views.detail import detail
from views.detail import detail_api

app = Flask(__name__, static_url_path = "", static_folder = "static", template_folder = "templates")

@app.errorhandler(HTTPException)
def not_found_error(error):
    background_color = ""
    tmp = error.code // 100

    if tmp == 4:
        background_color = "#0090e7"
    elif tmp == 5:
        background_color = "#e85f8e"
    
    return render_template("error-page.html", return_data = {
        "description" : error.description,
        "status_code" : error.code,
        "background_color" : background_color
    }), error.code

if __name__ == "__main__":
    app.register_blueprint(login.bp)
    app.register_blueprint(index.bp)
    app.register_blueprint(detail.bp)
    app.register_blueprint(detail_api.bp)

    app.config["SAVE_DIR_PATH"] = "/home/universe/Desktop/git/proxify/logs/"

    app.run(debug=True, host='0.0.0.0', port=8081)
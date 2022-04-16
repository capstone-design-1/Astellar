from flask import Flask
from flask_socketio import SocketIO
import os

socketio = SocketIO()

def createApp():
    from views.login import login
    from views.index import index
    from views.index import index_api
    from views.detail import detail
    from views.detail import detail_api
    from db.connect import createDatabase

    app = Flask(__name__, static_url_path = "", static_folder = "static", template_folder = "templates")
    app.register_blueprint(login.bp)
    app.register_blueprint(index.bp)
    app.register_blueprint(detail.bp)
    app.register_blueprint(detail_api.bp)
    app.register_blueprint(index_api.bp)
    createDatabase()

    app.config["SAVE_DIR_PATH"] = "/tmp/data/"
    app.config["SECRET_KEY"] = "test"

    try:
        if not os.path.exists(app.config["SAVE_DIR_PATH"]):
            os.makedirs(app.config["SAVE_DIR_PATH"])
    except OSError as e:
        print(f"[!] {app.config['SAVE_DIR_PATH']} 폴더를 생성하는 과정에서 에러가 발생 했습니다.")
        print(e)
        exit()

    socketio.init_app(app)

    return app
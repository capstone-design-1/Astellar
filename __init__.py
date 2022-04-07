from flask import Flask, render_template
from werkzeug.exceptions import HTTPException
from flask_socketio import SocketIO

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

    app.config["SAVE_DIR_PATH"] = "/tmp/data"
    app.config["SECRET_KEY"] = "test"

    socketio.init_app(app)

    return app
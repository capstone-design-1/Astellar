from flask import Flask
from flask_socketio import SocketIO
import os

socketio = SocketIO()

def createApp():
    """
    flask 서버를 실행하기 위해 필요한 환경 세팅 이후 Flask 객체를 리턴한다.

    blueprint를 세팅하여 각각의 페이지에 routing 을 설정한다.
    socket 기능을 사용하기 위해 flask_socketio 모듈을 사용한다.

    Raises:
        OSError: 폴더 생성 시, 권한 문제로 인해 발생하는 에러

    Returns:
        app: Flask 객체

    """

    from views.login import login
    from views.index import index
    from views.index import index_api
    from views.detail import detail
    from views.detail import detail_api
    from views.packet import packet
    from db.connect import createDatabase

    app = Flask(__name__, static_url_path = "", static_folder = "static", template_folder = "templates")
    app.register_blueprint(login.bp)
    app.register_blueprint(index.bp)
    app.register_blueprint(detail.bp)
    app.register_blueprint(detail_api.bp)
    app.register_blueprint(index_api.bp)
    app.register_blueprint(packet.bp)
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
from flask import Blueprint, request, abort

bp = Blueprint("detail-api", __name__, url_prefix = "/detail/api")

@bp.route("/subdomain", methods=["GET"])
def subdomain():
    target = request.args.get("target")
    
    if target == None:
        abort(400, description = "Parameter 'target' must be needed.")

    
    ## TODO
    ## subdomain 목록 가져오기
    return {
        "result" : [
            {
                "site" : "test.com",
                "status_code" : 200
            },
            {
                "site" : "test.com",
                "status_code" : 200
            },
            {
                "site" : "test.com",
                "status_code" : 200
            },
            {
                "site" : "test.com",
                "status_code" : 200
            },

        ]
    }
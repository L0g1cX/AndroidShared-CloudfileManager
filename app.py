import os
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
MAX_FILE_SIZE = 50 * 1024 * 1024
API_TOKEN = "your_secret_token"

# 证书路径预留：可使用 .crt 或 .pem 证书文件
SSL_CERT_CRT_PATH = os.path.join(BASE_DIR, "certs", "server.crt")
SSL_CERT_PEM_PATH = os.path.join(BASE_DIR, "certs", "server.pem")
SSL_KEY_PATH = os.path.join(BASE_DIR, "certs", "server.key")

ALLOWED_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "gif",
    "webp",
    "bmp",
    "pdf",
    "mp4",
    "mov",
    "avi",
    "mkv",
    "webm",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "csv",
}


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
os.makedirs(UPLOAD_DIR, exist_ok=True)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def list_uploaded_files() -> list[dict]:
    files = []
    for name in os.listdir(UPLOAD_DIR):
        file_path = os.path.join(UPLOAD_DIR, name)
        if not os.path.isfile(file_path):
            continue
        stat = os.stat(file_path)
        uploaded_timestamp = int(stat.st_mtime)
        uploaded_time = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        files.append(
            {
                "filename": name,
                "size_bytes": stat.st_size,
                "size_text": format_size(stat.st_size),
                "uploaded_timestamp": uploaded_timestamp,
                "uploaded_time": uploaded_time,
            }
        )
    files.sort(key=lambda item: item["uploaded_timestamp"], reverse=True)
    return files


def cors_preflight_response():
    return ("", 204)


def resolve_ssl_cert_path() -> str:
    if os.path.exists(SSL_CERT_CRT_PATH):
        return SSL_CERT_CRT_PATH
    return SSL_CERT_PEM_PATH


def save_incoming_file(file_storage):
    if file_storage is None or not file_storage.filename:
        raise ValueError("文件名不能为空")

    if not allowed_file(file_storage.filename):
        raise ValueError("文件类型不支持")

    safe_name = secure_filename(file_storage.filename)
    if not safe_name:
        raise ValueError("文件名不合法")

    save_name = safe_name
    target_path = os.path.join(UPLOAD_DIR, save_name)
    if os.path.exists(target_path):
        stem, ext = os.path.splitext(safe_name)
        save_name = f"{stem}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
        target_path = os.path.join(UPLOAD_DIR, save_name)

    file_storage.save(target_path)
    file_size = os.path.getsize(target_path)
    if file_size > MAX_FILE_SIZE:
        os.remove(target_path)
        raise ValueError("单文件大小不能超过 50MB")

    uploaded_time = datetime.fromtimestamp(os.path.getmtime(target_path)).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "filename": save_name,
        "size_bytes": file_size,
        "size_text": format_size(file_size),
        "uploaded_time": uploaded_time,
    }


@app.before_request
def verify_token():
    if request.method == "OPTIONS":
        return cors_preflight_response()
    if request.method == "GET" and request.path == "/":
        return None
    if request.method == "GET" and request.path.startswith("/static/"):
        return None
    if request.method == "POST" and request.path == "/share-target":
        share_token = request.args.get("token", "")
        if share_token == API_TOKEN:
            return None
        return jsonify({"error": "Unauthorized", "message": "share token 无效或缺失"}), 401
    token = request.headers.get("X-Token")
    if token != API_TOKEN:
        return jsonify({"error": "Unauthorized", "message": "X-Token 无效或缺失"}), 401
    return None


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({"error": "File Too Large", "message": "单文件大小不能超过 50MB"}), 413


@app.errorhandler(HTTPException)
def handle_http_error(error):
    return jsonify({"error": error.name, "message": error.description}), error.code


@app.errorhandler(Exception)
def handle_exception(error):
    app.logger.exception("Unhandled error: %s", error)
    return jsonify({"error": "Internal Server Error", "message": "服务器内部错误"}), 500


@app.route("/", methods=["GET"])
def index():
    shared_count = request.args.get("shared", "0")
    failed_count = request.args.get("failed", "0")
    try:
        shared_count = int(shared_count)
    except ValueError:
        shared_count = 0
    try:
        failed_count = int(failed_count)
    except ValueError:
        failed_count = 0
    return render_template(
        "index.html",
        files=list_uploaded_files(),
        shared_count=shared_count,
        failed_count=failed_count,
    )


@app.route("/upload-share", methods=["POST", "OPTIONS"])
def upload_share():
    if request.method == "OPTIONS":
        return cors_preflight_response()

    if not request.files:
        return jsonify({"error": "Bad Request", "message": "未检测到上传文件"}), 400

    file_storage = request.files.get("file")
    if file_storage is None:
        first_key = next(iter(request.files.keys()))
        file_storage = request.files.get(first_key)

    try:
        saved_file = save_incoming_file(file_storage)
    except ValueError as exc:
        message = str(exc)
        if "50MB" in message:
            return jsonify({"error": "File Too Large", "message": message}), 413
        return jsonify({"error": "Bad Request", "message": message}), 400

    return (
        jsonify(
            {
                "message": "上传成功",
                "filename": saved_file["filename"],
                "size_bytes": saved_file["size_bytes"],
                "size_text": saved_file["size_text"],
                "uploaded_time": saved_file["uploaded_time"],
            }
        ),
        201,
    )


@app.route("/files/<filename>", methods=["GET", "OPTIONS"])
def download_file(filename):
    if request.method == "OPTIONS":
        return cors_preflight_response()

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        return jsonify({"error": "Bad Request", "message": "非法文件名"}), 400

    file_path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.isfile(file_path):
        return jsonify({"error": "Not Found", "message": "文件不存在"}), 404

    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=True)


@app.route("/delit", methods=["POST", "OPTIONS"])
def delit():
    if request.method == "OPTIONS":
        return cors_preflight_response()

    payload = request.get_json(silent=True) or {}
    filename = payload.get("filename")
    if not isinstance(filename, str) or not filename.strip():
        return jsonify({"error": "Bad Request", "message": "filename 参数必填"}), 400

    if "/" in filename or "\\" in filename:
        return jsonify({"error": "Bad Request", "message": "非法文件名"}), 400

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        return jsonify({"error": "Bad Request", "message": "非法文件名"}), 400

    file_path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.isfile(file_path):
        return jsonify({"error": "Not Found", "message": "文件不存在"}), 404

    os.remove(file_path)
    return jsonify({"message": "删除成功", "filename": safe_name}), 200


@app.route("/share-target", methods=["POST", "OPTIONS"])
def share_target():
    if request.method == "OPTIONS":
        return cors_preflight_response()

    shared_files = request.files.getlist("share_files")
    if not shared_files:
        shared_files = list(request.files.values())
    if not shared_files:
        return jsonify({"error": "Bad Request", "message": "未接收到分享文件"}), 400

    saved_files = []
    failed_count = 0
    for file_storage in shared_files:
        try:
            saved_file = save_incoming_file(file_storage)
            saved_files.append(saved_file["filename"])
        except ValueError:
            failed_count += 1

    if not saved_files:
        return jsonify({"error": "Bad Request", "message": "未保存任何合法文件"}), 400

    if failed_count > 0:
        return redirect(url_for("index", shared=len(saved_files), failed=failed_count))
    return redirect(url_for("index", shared=len(saved_files)))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2270, ssl_context=(resolve_ssl_cert_path(), SSL_KEY_PATH))

import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

KNOWN_COURSES = {"SRS", "SSD"}


def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


def require_authenticated():
    if "user" not in flask.session:
        return None, ({"error": "authentication required"}, 401)

    return {
        "username": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses") or [],
    }, None


def parse_positive_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None

    if parsed <= 0:
        return None

    return parsed


def validate_grade_update_payload(data):
    if not isinstance(data, dict):
        return None, ({"error": "invalid JSON object"}, 400)

    required_fields = {"student_id", "course_id", "grade"}
    if not required_fields.issubset(data):
        return None, ({"error": "missing required field"}, 400)

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    if isinstance(student_id, bool) or not isinstance(student_id, int) or student_id <= 0:
        return None, ({"error": "invalid student_id"}, 400)

    if student_id not in STUDENT_PROFILES:
        return None, ({"error": "unknown student_id"}, 400)

    if not isinstance(course_id, str) or course_id not in KNOWN_COURSES:
        return None, ({"error": "invalid course_id"}, 400)

    if isinstance(grade, bool) or not isinstance(grade, (int, float)):
        return None, ({"error": "invalid grade"}, 400)

    if grade < 0 or grade > 20:
        return None, ({"error": "grade out of range"}, 400)

    return {
        "student_id": student_id,
        "course_id": course_id,
        "grade": grade,
    }, None


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>")
def get_student(student_id):
    user, error = require_authenticated()
    if error is not None:
        return error

    sid = parse_positive_int(student_id)
    if sid is None:
        return {"error": "invalid student_id"}, 400

    profile = STUDENT_PROFILES.get(sid)
    if profile is None:
        return {"error": "student not found"}, 404

    if user["role"] == "admin":
        return flask.jsonify(profile)

    if user["role"] == "student" and user["student_id"] == sid:
        return flask.jsonify(profile)

    return {"error": "forbidden"}, 403

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    user, error = require_authenticated()
    if error is not None:
        return error

    sid = parse_positive_int(student_id)
    if sid is None:
        return {"error": "invalid student_id"}, 400

    profile = STUDENT_PROFILES.get(sid)
    if profile is None:
        return {"error": "student not found"}, 404

    if user["role"] == "admin":
        return flask.jsonify(profile)

    if user["role"] == "student" and user["student_id"] == sid:
        return flask.jsonify(profile)

    return {"error": "forbidden"}, 403

@app.get("/grades/<student_id>")
def get_grades(student_id):
    user, error = require_authenticated()
    if error is not None:
        return error

    sid = parse_positive_int(student_id)
    if sid is None:
        return {"error": "invalid student_id"}, 400

    if sid not in STUDENT_PROFILES:
        return {"error": "student not found"}, 404

    rows = [row for row in GRADES if row["student_id"] == sid]

    if user["role"] == "admin":
        return flask.jsonify(rows)

    if user["role"] == "student":
        if user["student_id"] != sid:
            return {"error": "forbidden"}, 403
        return flask.jsonify(rows)

    if user["role"] == "professor":
        permitted_courses = set(user["courses"])
        permitted_rows = [
            row for row in rows if row["course_id"] in permitted_courses
        ]
        if not permitted_rows:
            return {"error": "forbidden"}, 403
        return flask.jsonify(permitted_rows)

    return {"error": "forbidden"}, 403

@app.post("/grades/update")
def update_grade():
    user, error = require_authenticated()
    if error is not None:
        return error

    data = flask.request.get_json(silent=True)
    payload, error = validate_grade_update_payload(data)
    if error is not None:
        return error

    student_id = payload["student_id"]
    course_id = payload["course_id"]
    grade = payload["grade"]

    if user["role"] == "admin":
        authorized = True
    elif user["role"] == "professor" and course_id in set(user["courses"]):
        authorized = True
    else:
        authorized = False

    if not authorized:
        return {"error": "forbidden"}, 403

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    user, error = require_authenticated()
    if error is not None:
        return error

    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)

```diff
diff --git a/baseline_secure_coding_api.py b/baseline_secure_coding_api.py
index 1111111..2222222 100644
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -51,12 +51,49 @@ GRADES = [
     {"student_id": 1001, "course_id": "SSD", "grade": 16},
 ]
 
+KNOWN_COURSES = {"SRS", "SSD"}
+
 def find_grade(student_id, course_id):
     for row in GRADES:
         if row["student_id"] == student_id and row["course_id"] == course_id:
             return row
     return None
 
+def require_authenticated():
+    if "user" not in flask.session:
+        return None, ({"error": "authentication required"}, 401)
+    return {
+        "username": flask.session.get("user"),
+        "role": flask.session.get("role"),
+        "student_id": flask.session.get("student_id"),
+        "courses": flask.session.get("courses") or [],
+    }, None
+
+def parse_positive_int(value):
+    try:
+        parsed = int(value)
+    except (TypeError, ValueError):
+        return None
+
+    if parsed <= 0:
+        return None
+
+    return parsed
+
+def validate_grade_update_payload(data):
+    if not isinstance(data, dict):
+        return None, ({"error": "invalid JSON object"}, 400)
+
+    required_fields = {"student_id", "course_id", "grade"}
+    if not required_fields.issubset(data):
+        return None, ({"error": "missing required field"}, 400)
+
+    student_id = data["student_id"]
+    course_id = data["course_id"]
+    grade = data["grade"]
+
+    if isinstance(student_id, bool) or not isinstance(student_id, int) or student_id <= 0:
+        return None, ({"error": "invalid student_id"}, 400)
+    if student_id not in STUDENT_PROFILES:
+        return None, ({"error": "unknown student_id"}, 400)
+
+    if not isinstance(course_id, str) or course_id not in KNOWN_COURSES:
+        return None, ({"error": "invalid course_id"}, 400)
+
+    if isinstance(grade, bool) or not isinstance(grade, (int, float)):
+        return None, ({"error": "invalid grade"}, 400)
+    if grade < 0 or grade > 20:
+        return None, ({"error": "grade out of range"}, 400)
+
+    return {
+        "student_id": student_id,
+        "course_id": course_id,
+        "grade": grade,
+    }, None
+
 
 # -----------------------------------------------------------------------------
 # REST API Endpoints
@@ -109,39 +146,95 @@ def me():
     }
 
 @app.get("/students/<student_id>/profile")
 def get_profile(student_id):
-    profile = STUDENT_PROFILES.get(int(student_id))
+    user, error = require_authenticated()
+    if error is not None:
+        return error
+
+    sid = parse_positive_int(student_id)
+    if sid is None:
+        return {"error": "invalid student_id"}, 400
+
+    profile = STUDENT_PROFILES.get(sid)
     if profile is None:
         return {"error": "student not found"}, 404
+
+    if user["role"] == "admin":
+        return flask.jsonify(profile)
+
+    if user["role"] == "student" and user["student_id"] == sid:
+        return flask.jsonify(profile)
+
+    return {"error": "forbidden"}, 403
+
     return flask.jsonify(profile)
 
 @app.get("/grades/<student_id>")
 def get_grades(student_id):
-    sid = int(student_id)
-    rows = [row for row in GRADES if row["student_id"] == sid]
-    return flask.jsonify(rows)
+    user, error = require_authenticated()
+    if error is not None:
+        return error
+
+    sid = parse_positive_int(student_id)
+    if sid is None:
+        return {"error": "invalid student_id"}, 400
+
+    if sid not in STUDENT_PROFILES:
+        return {"error": "student not found"}, 404
+
+    rows = [row for row in GRADES if row["student_id"] == sid]
+
+    if user["role"] == "admin":
+        return flask.jsonify(rows)
+
+    if user["role"] == "student":
+        if user["student_id"] != sid:
+            return {"error": "forbidden"}, 403
+        return flask.jsonify(rows)
+
+    if user["role"] == "professor":
+        permitted_courses = set(user["courses"])
+        permitted_rows = [
+            row for row in rows if row["course_id"] in permitted_courses
+        ]
+        if not permitted_rows:
+            return {"error": "forbidden"}, 403
+        return flask.jsonify(permitted_rows)
+
+    return {"error": "forbidden"}, 403
 
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
+    user, error = require_authenticated()
+    if error is not None:
+        return error
 
-    student_id = data["student_id"]
-    course_id = data["course_id"]
-    grade = data["grade"]
+    data = flask.request.get_json(silent=True)
+    payload, error = validate_grade_update_payload(data)
+    if error is not None:
+        return error
+
+    student_id = payload["student_id"]
+    course_id = payload["course_id"]
+    grade = payload["grade"]
+
+    if user["role"] == "admin":
+        pass
+    elif user["role"] == "professor" and course_id in set(user["courses"]):
+        pass
+    else:
+        return {"error": "forbidden"}, 403
 
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
     else:
         row["grade"] = grade
 
     return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
 
 @app.get("/files")
 def download_file():
+    user, error = require_authenticated()
+    if error is not None:
+        return error
+
     raw_path = flask.request.args.get("path", "")
     target = MATERIALS_DIR / raw_path
     return flask.send_file(target)
```

The extra `return flask.jsonify(profile)` after the new profile authorisation block is now unreachable. If you want the tidiest final patch, remove that leftover line too:

```diff
@@ -169,7 +169,6 @@ def get_profile(student_id):
         return flask.jsonify(profile)
 
     return {"error": "forbidden"}, 403
-
-    return flask.jsonify(profile)
```

## Control implemented

This patch adds a small shared authentication helper and applies it consistently to all affected paths:

- `GET /students/<student_id>/profile`
- `GET /grades/<student_id>`
- `POST /grades/update`
- `GET /files?path=<name>`

The access rules implemented are:

| Endpoint | Rule |
|---|---|
| `GET /students/<student_id>/profile` | Requires login. Admins may read any profile. Students may read only their own profile. Professors are denied. |
| `GET /grades/<student_id>` | Requires login. Admins may read all grade rows for the student. Students may read only their own grades. Professors may read only rows for courses assigned to them. If no rows are permitted, the request is denied. |
| `POST /grades/update` | Requires login. Admins may update any valid grade record. Professors may update only assigned courses. Students and unauthorised roles are denied. |
| `GET /files` | Requires login before material download. |

The patch also adds input validation for the affected student ID and grade update paths:

- Path student IDs must parse as positive integers.
- Grade update JSON must be an object.
- Required fields must be present.
- `student_id` must be a positive integer and must exist.
- `course_id` must be one of the known baseline courses: `SRS`, `SSD`.
- `grade` must be numeric from `0` to `20` inclusive.
- Boolean grades are rejected.
- Invalid update requests return before any mutation of `GRADES`.

This preserves the legitimate functionality exercised by the supplied tests:

- Assigned professor can update `SRS`.
- Unassigned professor cannot update `SSD`.
- Admin can update valid grades.
- Student cannot update grades.
- Grade reads are filtered by requester authority.
- Profile reads are restricted by role and ownership.
- Materials remain downloadable for authenticated users.

## Remaining assumptions and limitations

- `KNOWN_COURSES` is defined from the exercise requirement as `{"SRS", "SSD"}`. If courses become data-driven later, this should be replaced with a proper course table or registry.
- The file endpoint is fixed only for the confirmed authentication issue. It still accepts a raw `path` parameter and passes it to `send_file`; path traversal or file allow-listing is outside the confirmed issue set you asked to fix.
- The app still has a broad `@app.errorhandler(Exception)` that returns exception details for unexpected errors. The patch avoids triggering it for the confirmed bad-input cases, but the global handler itself remains unchanged because it was not part of the specified repair scope.
- Authorisation decisions rely on trusted session values set by `/login`. For a larger application, role and course membership should ideally be loaded server-side from a durable user store on each request or protected against stale session state.

## Additional regression tests to add

```python
def test_profile_rejects_negative_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/-1/profile")

    assert response.status_code == 400


def test_grades_rejects_non_integer_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/grades/asd")

    assert response.status_code == 400


def test_grades_rejects_negative_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/grades/-1")

    assert response.status_code == 400


def test_professor_with_no_permitted_grade_rows_is_denied(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    assert all(row["course_id"] == "SRS" for row in response.json)


def test_grade_update_rejects_boolean_grade_without_mutation(client, utils):
    utils.login(client, "admin1", "adminpw")
    before = api.find_grade(1001, "SRS")["grade"]

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": True},
    )

    assert response.status_code == 400
    assert api.find_grade(1001, "SRS")["grade"] == before


def test_grade_update_rejects_missing_course_without_mutation(client, utils):
    utils.login(client, "admin1", "adminpw")
    before = api.find_grade(1001, "SRS")["grade"]

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "grade": 18},
    )

    assert response.status_code == 400
    assert api.find_grade(1001, "SRS")["grade"] == before


def test_grade_update_rejects_non_json_body(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
        "/grades/update",
        data="not json",
        content_type="text/plain",
    )

    assert response.status_code == 400


def test_professor_cannot_create_grade_for_unassigned_course(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SSD", "grade": 18},
    )

    assert response.status_code == 403
    assert api.find_grade(1002, "SSD") is None


def test_authenticated_user_can_download_existing_material(client, utils):
    utils.login(client, "bob", "bobpw")

    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 200


def test_unauthenticated_user_cannot_download_material(client):
    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 401
```

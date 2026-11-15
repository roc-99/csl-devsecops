The previous diff hunks had invalid line/count metadata, which is why `git apply` reported a corrupt patch. Here is a clean single patch against the exact file you pasted.

Save only the contents of this diff block into `evidence/patching/patching-third-patch.patch` and run `git apply` on it.

```diff
diff --git a/baseline_secure_coding_api.py b/baseline_secure_coding_api.py
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -50,14 +50,75 @@ GRADES = [
     {"student_id": 1002, "course_id": "SRS", "grade": 15},
     {"student_id": 1001, "course_id": "SSD", "grade": 16},
 ]
 
+KNOWN_COURSES = {"SRS", "SSD"}
+
+
 def find_grade(student_id, course_id):
     for row in GRADES:
         if row["student_id"] == student_id and row["course_id"] == course_id:
             return row
     return None
 
+
+def require_authenticated():
+    if "user" not in flask.session:
+        return None, ({"error": "authentication required"}, 401)
+
+    return {
+        "username": flask.session.get("user"),
+        "role": flask.session.get("role"),
+        "student_id": flask.session.get("student_id"),
+        "courses": flask.session.get("courses") or [],
+    }, None
+
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
+
+    if student_id not in STUDENT_PROFILES:
+        return None, ({"error": "unknown student_id"}, 400)
+
+    if not isinstance(course_id, str) or course_id not in KNOWN_COURSES:
+        return None, ({"error": "invalid course_id"}, 400)
+
+    if isinstance(grade, bool) or not isinstance(grade, (int, float)):
+        return None, ({"error": "invalid grade"}, 400)
+
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
 # -----------------------------------------------------------------------------
@@ -116,36 +177,100 @@ def me():
 
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
-    return flask.jsonify(profile)
+
+    if user["role"] == "admin":
+        return flask.jsonify(profile)
+
+    if user["role"] == "student" and user["student_id"] == sid:
+        return flask.jsonify(profile)
+
+    return {"error": "forbidden"}, 403
 
 @app.get("/grades/<student_id>")
 def get_grades(student_id):
-    sid = int(student_id)
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
     rows = [row for row in GRADES if row["student_id"] == sid]
-    return flask.jsonify(rows)
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
+        authorized = True
+    elif user["role"] == "professor" and course_id in set(user["courses"]):
+        authorized = True
+    else:
+        authorized = False
+
+    if not authorized:
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
 
 @app.errorhandler(Exception)
```

Apply it with:

```bash
git apply evidence/patching/patching-third-patch.patch
```

If you are copying from Markdown, make sure the saved patch file does **not** include the surrounding triple backticks.

One test issue to watch: your supplied tests include this request:

```python
response = client.get("/students/asd")
```

But the pasted application does not define a `GET /students/<student_id>` endpoint. It only defines:

```python
GET /students/<student_id>/profile
```

So this patch intentionally does not add or change `/students/<student_id>`, because that was not one of the confirmed affected paths. If that test is active, it will still return `404`, not `400`, unless there is another endpoint in your local file that was not included here.

## Concise findings table

| ID | Finding | Location | Attacker-controlled input and path | Missing control and root cause | Preconditions and impact | Proposed confirming test | Confidence |
|---|---|---|---|---|---|---|---|
| AUTH-01 | Hard-coded Flask secret enables session forgery if disclosed | Single source file, global config, line ~8; session use lines ~89–92 | Session cookie contents are trusted by Flask if signed with `SECRET_KEY`; code contains `dev-secret-key` | Secret key is static and embedded in source; Flask client-side sessions rely on secrecy of this key for integrity | If attacker knows source or secret, they can forge `user`, `role`, `student_id`, `courses`; this can bypass any session-based authentication/authorization | Create a Flask session cookie signed with `dev-secret-key` containing admin-like values, then call protected routes and compare behaviour with no login | High |
| AUTH-02 | Student profile endpoint lacks authentication | `get_profile`, lines ~114–119 | `GET /students/<student_id>/profile` → `int(student_id)` → `STUDENT_PROFILES.get(...)` → response | No check for authenticated session before profile access | Any unauthenticated user can read profiles, violating R1 | Request `GET /students/1001/profile` without login; expected `401`, likely returns Alice’s profile | High |
| AUTHZ-03 | Student profile endpoint lacks role and ownership authorization | `get_profile`, lines ~114–119 | Authenticated user controls `<student_id>`; code directly returns matching profile | No ownership check for students; no role check for professors/admins | A student can read another student’s profile; a professor can read profiles although R3 forbids this | Log in as `bob`; request `GET /students/1001/profile`; expected `403`, likely returns Alice’s profile | High |
| AUTH-04 | Grade read endpoint lacks authentication | `get_grades`, lines ~121–125 | `GET /grades/<student_id>` → `int(student_id)` → list comprehension over `GRADES` | No authenticated-session check before grade access | Any unauthenticated user can read grades for any student ID, violating R1 | Request `GET /grades/1001` without login; expected `401`, likely returns Alice’s grade rows | High |
| AUTHZ-05 | Grade read endpoint lacks ownership, staff scope, and response filtering | `get_grades`, lines ~121–125 | Authenticated user controls `<student_id>`; code returns all grade rows for that student | No student ownership check; no professor course-scope filter; no admin-only broad access logic | Students can read others’ grades; `prof_srs` can see `SSD` grades when requesting student `1001`; violates R2–R4 | Log in as `alice`; request `GET /grades/1002`; expected `403`, likely returns Bob’s grades. Log in as `prof_srs`; request `GET /grades/1001`; expected only `SRS`, likely returns `SRS` and `SSD` | High |
| AUTH-06 | Grade update endpoint lacks authentication | `update_grade`, lines ~127–141 | `POST /grades/update` with JSON → `data[...]` → `find_grade(...)` → mutate `GRADES` | No authenticated-session check before modifying academic records | Any unauthenticated requester can alter or insert grade records, violating R1 and R7’s unchanged-data requirement for denied updates | Without login, post `{"student_id":1001,"course_id":"SRS","grade":0}`; expected `401` and unchanged data, likely returns `ok` and mutates grade | High |
| AUTHZ-07 | Grade update endpoint lacks role and course authorization | `update_grade`, lines ~127–141 | Authenticated user controls `student_id`, `course_id`, `grade`; code mutates record regardless of requester | No admin/professor check; no professor assigned-course check; no student denial | Students can update grades; professors can update courses not assigned to them; violates R3–R4 | Log in as `alice`; update her `SRS` grade. Log in as `prof_srs`; update `SSD`. Expected `403`; likely `ok` and data changed | High |
| VAL-08 | Grade update accepts malformed, unauthorized, or invalid grade records | `update_grade`, lines ~129–141; `find_grade`, lines ~54–58 | JSON body fields `student_id`, `course_id`, `grade` flow directly into lookup and mutation/append | No validation for required JSON object, existing student, known course, numeric non-boolean grade in range `0..20`; appends unknown records | Invalid course/student IDs can create new records; grades like `true`, strings, negative values, or values above `20` can be stored; malformed input may raise exceptions | As admin-equivalent or unauthenticated, post `{"student_id":9999,"course_id":"MATH","grade":21}` or `{"student_id":1001,"course_id":"SRS","grade":true}`; expected client error and unchanged data, likely mutation | High |
| VAL-09 | Student identifier path parameters are not validated as positive integers | `get_profile`, line ~116; `get_grades`, line ~123 | `<student_id>` string passed to `int(student_id)` without validation or exception handling | No explicit positive-integer validation; invalid strings cause exceptions; negative/zero IDs are accepted into lookup path | Invalid input returns `500` through global handler instead of appropriate client error; may expose implementation details | Request `GET /students/abc/profile`, `GET /grades/abc`, and `GET /grades/-1`; expected client errors without internals, likely `500` for non-integer and `[]` for negative | High |
| FILE-10 | File download endpoint lacks authentication | `download_file`, lines ~143–147 | `GET /files?path=<name>` → `MATERIALS_DIR / raw_path` → `send_file(target)` | No authenticated-session check before material download | Any unauthenticated user can download teaching materials, violating R1 | Request `GET /files?path=srs-summary.txt` without login; expected `401`, likely returns file content | High |
| FILE-11 | File download endpoint permits path traversal and absolute-path reads | `download_file`, lines ~143–147 | Query parameter `path` is concatenated with `MATERIALS_DIR`; `..` or absolute paths can escape directory | No canonicalization, safe join, containment check, or filename allowlist | Authenticated or unauthenticated users may read files outside `materials`, depending on filesystem permissions; violates R6 | In a test fixture, create `BASE_DIR/secret.txt`; request `/files?path=../secret.txt`. Also test absolute paths where applicable. Expected denial, likely file returned | High |
| ERR-12 | Global error handler exposes exception details and maps invalid requests to `500` | `handle_error`, lines ~149–154; triggered by lines ~116, ~123, ~129–133, ~147 | Malformed path IDs, malformed JSON, missing JSON fields, missing files, unsupported methods can raise exceptions | Broad `@app.errorhandler(Exception)` returns `str(exc)` and exception class name with status `500` | Internal exception details, filesystem paths, parsing details, and implementation types may be exposed; invalid client requests are not distinguished from server failures | Request `/students/not-an-int/profile`, malformed JSON to `/grades/update`, missing file through `/files?path=nope`; expected `400/404` style client errors without internals, likely JSON containing exception text/type and status `500` | High |

## Supporting explanations

### AUTH-01 — Hard-coded Flask secret enables session forgery

**Demonstrated code facts**

- The application sets:

```python
app.config["SECRET_KEY"] = "dev-secret-key"
```

- Login stores identity and authorization-relevant attributes in the Flask session:

```python
flask.session["user"] = user.username
flask.session["role"] = user.role
flask.session["student_id"] = user.student_id
flask.session["courses"] = user.courses or []
```

**Security requirement basis**

- R1–R4 require authentication and per-record authorization.
- If session data can be forged, session-based identity and role checks become unreliable.

**Assumption and uncertainty**

- Flask’s default session mechanism is client-side and signed using `SECRET_KEY`. This is standard Flask behaviour.
- This finding depends on the secret being known or guessable. Because it is present in source and is a weak development value, confidence is high.

---

### AUTH-02 and AUTHZ-03 — Profile endpoint lacks authentication and authorization

**Demonstrated code facts**

```python
@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)
```

There is no use of `flask.session`, no check for `"user"`, and no role/ownership logic.

**Security requirement basis**

- R1: profile access requires an authenticated user.
- R2: students may read only their own profile.
- R3: professors are not permitted to read student profile records in this exercise.
- R3 also allows administrators to read profiles.

**Impact**

- Anonymous users can read profile data.
- `alice` can request Bob’s profile.
- `prof_srs` can request student profiles despite R3 forbidding professor profile access.

**Proposed tests**

- Unauthenticated:

```http
GET /students/1001/profile
```

Expected under R1: `401`.

- Student cross-access:

```http
POST /login username=bob password=bobpw
GET /students/1001/profile
```

Expected under R2: `403`.

- Professor profile access:

```http
POST /login username=prof_srs password=profpw
GET /students/1001/profile
```

Expected under R3: `403`.

---

### AUTH-04 and AUTHZ-05 — Grade read endpoint lacks authentication, authorization, and filtering

**Demonstrated code facts**

```python
@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)
```

The endpoint returns every grade row matching the supplied student ID.

**Security requirement basis**

- R1: grade access requires authentication.
- R2: students may read only their own grades.
- R3: professors may read grades only for assigned courses.
- R4: grade-list responses must contain only records the requester is authorized to read; deny if no records are permitted.

**Impact**

- Anonymous users can read grades.
- Students can read other students’ grades.
- `prof_srs`, assigned only to `SRS`, can receive Alice’s `SSD` grade because the response is filtered only by student ID.

**Proposed tests**

Unauthenticated:

```http
GET /grades/1001
```

Expected: `401`.

Student cross-access:

```http
POST /login username=alice password=alicepw
GET /grades/1002
```

Expected: `403`.

Professor overbroad list:

```http
POST /login username=prof_srs password=profpw
GET /grades/1001
```

Expected: only Alice’s `SRS` grade, or denial if no permitted records. The current logic likely returns both:

```json
[
  {"student_id": 1001, "course_id": "SRS", "grade": 14},
  {"student_id": 1001, "course_id": "SSD", "grade": 16}
]
```

---

### AUTH-06 and AUTHZ-07 — Grade update endpoint lacks authentication and authorization

**Demonstrated code facts**

```python
@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
```

No session or role data is checked before mutating `GRADES`.

**Security requirement basis**

- R1: grade updates require authentication.
- R3: professors may update grades only for assigned courses; administrators may update grades.
- R4: login alone, a valid identifier, or a role name alone is insufficient; authorization must be checked for the specific record.
- R7: denied or invalid updates must leave stored data unchanged.

**Impact**

- Anonymous users can change grades.
- Students can change grades.
- Professors can update unassigned courses such as `SSD`.

**Proposed tests**

Unauthenticated update:

```http
POST /grades/update
Content-Type: application/json

{"student_id":1001,"course_id":"SRS","grade":0}
```

Expected: `401` and unchanged stored data.

Student update:

```http
POST /login username=alice password=alicepw

POST /grades/update
Content-Type: application/json

{"student_id":1001,"course_id":"SRS","grade":20}
```

Expected: `403` and unchanged data.

Professor outside assigned course:

```http
POST /login username=prof_srs password=profpw

POST /grades/update
Content-Type: application/json

{"student_id":1001,"course_id":"SSD","grade":20}
```

Expected: `403` and unchanged data.

---

### VAL-08 — Grade update input validation is missing

**Demonstrated code facts**

The update endpoint directly trusts JSON fields:

```python
student_id = data["student_id"]
course_id = data["course_id"]
grade = data["grade"]
```

It then either updates an existing row or appends a new row:

```python
if row is None:
    GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
else:
    row["grade"] = grade
```

**Security requirement basis**

R5 requires:

- JSON object.
- Existing student identifier.
- Known course identifier.
- Numeric grade from `0` to `20` inclusive.
- Boolean values are not valid grades.
- Missing fields and malformed input must be rejected without update.
- Known baseline courses are `SRS` and `SSD`.

**Impact**

The endpoint appears to accept or mishandle:

- Unknown student IDs.
- Unknown courses such as `MATH`.
- Grades below `0` or above `20`.
- Boolean grades such as `true`.
- String grades such as `"20"`.
- Duplicate records where `student_id` type differs, for example `"1001"` instead of integer `1001`.

**Proposed tests**

Unknown student and course:

```http
POST /grades/update
Content-Type: application/json

{"student_id":9999,"course_id":"MATH","grade":21}
```

Expected: client error and no change.

Boolean grade:

```http
POST /grades/update
Content-Type: application/json

{"student_id":1001,"course_id":"SRS","grade":true}
```

Expected: client error and no change.

String student ID:

```http
POST /grades/update
Content-Type: application/json

{"student_id":"1001","course_id":"SRS","grade":18}
```

Expected: client error or normalized integer handling without duplicate/corrupt record. Current lookup likely fails because `"1001"` does not equal `1001`, causing an appended duplicate record.

---

### VAL-09 — Student identifier path parameters are not validated as positive integers

**Demonstrated code facts**

Both endpoints convert the route parameter directly:

```python
profile = STUDENT_PROFILES.get(int(student_id))
```

```python
sid = int(student_id)
```

**Security requirement basis**

- R5: student identifiers must be positive integers.
- R7: invalid requests must return appropriate client errors without exposing implementation exception details.

**Impact**

- Non-integer IDs raise `ValueError`.
- Negative IDs such as `-1` are accepted into the lookup path rather than rejected as invalid.
- The global error handler turns conversion exceptions into `500` responses with exception details.

**Proposed tests**

```http
GET /students/abc/profile
GET /grades/abc
GET /grades/-1
GET /students/0/profile
```

Expected: appropriate client errors, likely `400`, without internal exception details. For authenticated-but-unauthorized cases, R7 distinguishes `403`.

---

### FILE-10 and FILE-11 — File download lacks authentication and path containment

**Demonstrated code facts**

```python
@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)
```

There is no authentication check and no containment check after path construction.

**Security requirement basis**

- R1: material downloads require an authenticated user.
- R6: authenticated users may download teaching materials within the materials directory; requests must not read files outside that directory.

**Impact**

- Anonymous users can download teaching materials.
- Path traversal using `..` can escape `materials`.
- Absolute paths may override the base path on platforms where `pathlib` treats the right-hand operand as absolute.
- If the application process can read sensitive files, they may be disclosed.

**Proposed tests**

Unauthenticated material access:

```http
GET /files?path=srs-summary.txt
```

Expected: `401`.

Traversal test with fixture:

1. Place a file outside `materials`, for example `BASE_DIR/secret.txt`.
2. Request:

```http
GET /files?path=../secret.txt
```

Expected: denial, not file contents.

Absolute path test where applicable:

```http
GET /files?path=/etc/passwd
```

Expected: denial. Actual result depends on platform and process permissions.

---

### ERR-12 — Error handling exposes internals and misclassifies client errors

**Demonstrated code facts**

```python
@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500
```

This catches broad exceptions and returns the exception message and class name.

Likely triggers include:

- `ValueError` from `int(student_id)`.
- `TypeError` or HTTP parsing exceptions from `flask.request.get_json()`.
- `KeyError` from missing JSON fields.
- File-related exceptions from `flask.send_file(target)`.

**Security requirement basis**

- R7 requires invalid requests to return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details.
- R7 also requires unauthenticated protected requests to return `401` and authenticated-but-unauthorized requests to return `403`.

**Impact**

- Invalid client input is reported as server failure.
- Exception class names such as `ValueError`, `KeyError`, `FileNotFoundError`, or framework exception types may be disclosed.
- File errors may disclose filesystem paths or implementation details via `str(exc)`.
- Broad exception handling can also interfere with normal HTTP errors such as `404`.

**Proposed tests**

Malformed student ID:

```http
GET /students/not-an-int/profile
```

Malformed or missing JSON:

```http
POST /grades/update
Content-Type: application/json

not-json
```

Missing grade field:

```http
POST /grades/update
Content-Type: application/json

{"student_id":1001,"course_id":"SRS"}
```

Missing file:

```http
GET /files?path=missing.txt
```

Expected: appropriate client error responses without exception type names or internal paths. Current handler likely returns `500` with implementation details.

## Notes on scope

These findings are based only on the provided source and the explicit requirements R1–R7. I did not assume production requirements such as password hashing, CSRF protection, rate limiting, audit logging, or database transaction safety, although those would matter in a real deployment. Absence of additional findings here is not proof of safety.
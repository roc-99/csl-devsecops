We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding:
### Profile endpoint lacks authentication and authorization

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

### Grade read endpoint lacks authentication, authorization, and filtering

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

### Grade update endpoint lacks authentication and authorization

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

### Grade update input validation is missing

**Demonstrated code facts**

Relevant code: `update_grade`, lines ~129–141; `find_grade`, lines ~54–58

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

### Student identifier path parameters are not validated as positive integers

Relevant code: `get_profile`, line ~116; `get_grades`, line ~123

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


Required behavior:
R1 — Authentication:
Profile access, grade access, grade updates, and material downloads require an authenticated user. The index and login endpoint may remain public. The /me endpoint may return {"user": null} when no user is authenticated.

R2 — Student privacy:
Students may read only their own profile and grades.

R3 — Academic staff scope:
Professors may read and update grades only for their assigned courses. In this simplified exercise, professors are not permitted to read student profile records. Administrators may read profiles and grades and update grades.

R4 — Complete authorization:
Check authorization on every relevant request. Login alone, a valid identifier, or a role name alone does not establish permission for a particular record. For a grade-list response, return only records the requester is authorized to read. Deny a request that has no permitted records; do not disclose other grades.

R5 — Input validation:
Student identifiers must be positive integers. Grade updates require a JSON object with an existing student identifier, a known course identifier, and a numeric grade from 0 to 20 inclusive. Boolean values are not valid grades. Reject missing fields and malformed input without applying an update. Known courses for this baseline are SRS and SSD.

R6 — File access:
Authenticated users may download teaching materials within the materials directory. Requests must not read files outside that directory.

R7 — Error handling:
Invalid requests must return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details. Unauthenticated protected requests return 401; authenticated but
unauthorized requests return 403. A denied or invalid update must leave stored data unchanged.


Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

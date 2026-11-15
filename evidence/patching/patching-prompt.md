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

FILE-10 — File download lacks authentication

Demonstrated code facts

@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

There is no authentication check.

Security requirement basis

    R1: material downloads require an authenticated user.

Required behavior:
Only fix the above specified problems.

The following tests were created.

import baseline_secure_coding_api as api

#----------------- Grade update -------------------
def test_assigned_professor_can_update_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")
    
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_admin_can_update_grade(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_unassigned_professor_cannot_update_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")
    
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 18},
    )

    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == 16

def test_student_cannot_update_grade(client, utils):
    utils.login(client, "alice", "alicepw")
    
    response = client.post(
            "/grades/update",
            json= {
                    "student_id": 1001,
                    "course_id": "SRS",
                    "grade": 18,
                }
            )

    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14

def test_unauthencated_cannot_update_grade(client):
    response = client.post(
            "/grades/update",
            json= {
                    "student_id": 1001,
                    "course_id": "SRS",
                    "grade": 18,
                }
            )
    
    assert response.status_code == 401
    assert api.find_grade(1001, "SRS")["grade"] == 14

#---------------------- Grade read --------------------
def test_assigned_professor_can_see_student_grades(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200

    for grade in response.json:
        assert grade["course_id"] == "SRS"

def test_student_can_see_own_grades(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/grades/1001")

    assert response.status_code == 200

    for grade in response.json:
        assert grade["student_id"] == 1001

def test_admin_can_see_student_grades(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    assert len(response.json) == 2

def test_student_cannot_see_other_student_grades(client, utils):
    utils.login(client, "bob", "bobpw")

    response = client.get("/grades/1001")

    assert response.status_code == 403
    # Maybe add check to see if response still came

def test_unauthenticated_cannot_see_student_grades(client):
    response = client.get("/grades/1001")

    assert response.status_code == 401

def test_invalid_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/asd")

    assert response.status_code == 400

def test_non_existent_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/11")

    assert response.status_code == 404
    
def test_invalid_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/asd/profile")

    assert response.status_code == 400

def test_non_existent_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/11/profile")

    assert response.status_code == 404
    
import baseline_secure_coding_api as api

def test_professor_can_change_grade(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_invalid_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": "asd", "course_id": "SRS", "grade": 18}
        )

    assert response.status_code == 400

def test_non_existing_student_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 11, "course_id": "SRS", "grade": 18}
        )

    assert response.status_code == 400

def test_invalid_course_id(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "asd", "grade": 18}
        )

    assert response.status_code == 400

def test_invalid_grade(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": "A+"}
        )

    assert response.status_code == 400

def test_out_of_range_grade_1(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": -1}
        )

    assert response.status_code == 400

def test_out_of_range_grade_2(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 21}
        )

    assert response.status_code == 400

def test_empty_json_request(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.post(
            "/grades/update",
            json={}
        )

    assert response.status_code == 400
    
def test_student_can_read_materials(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 200

def test_unautherized_cannot_read_materials(client, utils):
    response = client.get("/files?path=secure-coding.txt")

    assert response.status_code == 401

def test_student_can_see_own_profile(client, utils):
    utils.login(client, "alice", "alicepw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200

def test_admin_can_see_student_profile(client, utils):
    utils.login(client, "admin1", "adminpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200

def test_student_cannot_see_other_student_profile(client, utils):
    utils.login(client, "bob", "bobpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 403

def test_professor_cannot_see_student_profile(client, utils):
    utils.login(client, "prof_srs", "profpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 403

def test_unauthenticated_cannot_see_student_profile(client):
    response = client.get("/students/1001/profile")

    assert response.status_code == 401

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

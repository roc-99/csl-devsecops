## Findings table

| ID | Finding | Affected location | Attacker-controlled input and path | Missing or incorrect control | Preconditions and impact | Proposed confirmation test | Confidence |
|---|---|---|---|---|---|---|---|
| F-01 | Unauthenticated access to student profiles | Provided source, `get_profile`, lines 116–121 | URL path parameter `student_id` → `int(student_id)` → `STUDENT_PROFILES.get(...)` → returned by `jsonify` | No authentication check before returning profile data | If profiles are intended to be private to the student, authorised professors, or admins, any user can enumerate/read student PII such as name and email | Without logging in, request `GET /students/1001/profile` and verify that Alice’s profile is returned | High for code fact; medium for policy assumption |
| F-02 | Unauthenticated access to grades | `get_grades`, lines 123–127 | URL path parameter `student_id` → filter over `GRADES` → returned by `jsonify` | No authentication or authorisation check | If grades are confidential academic records, any unauthenticated requester can read any student’s grades | Without logging in, request `GET /grades/1001` and verify grade records are returned | High for code fact; high for likely impact |
| F-03 | Unauthenticated and unauthorised grade modification | `update_grade`, lines 129–143; `find_grade`, lines 56–60 | JSON body fields `student_id`, `course_id`, `grade` → lookup/update/append in global `GRADES` | No authentication; no role check; no professor course check; no grade validation | Any requester can create or alter grades for any student/course. If professors should only update assigned courses and students should not update grades, this is a full integrity failure | Without logging in, POST JSON such as `{"student_id":1001,"course_id":"SRS","grade":20}` to `/grades/update`, then read `/grades/1001` | High |
| F-04 | Path traversal and arbitrary file read via materials download | `download_file`, lines 145–149 | Query parameter `path` → `target = MATERIALS_DIR / raw_path` → `flask.send_file(target)` | No path canonicalisation, allowlist, or containment check under `MATERIALS_DIR` | Any requester may read files outside the materials directory that the process can access. Absolute paths may also override the base path depending on platform/path semantics | Request `GET /files?path=../<known-file>` or an absolute readable path and verify whether content outside `materials` is returned | High |
| F-05 | Hardcoded predictable Flask secret key enables session forgery if known | App config, line 8; session use lines 91–94 and 108–113 | Attacker-supplied signed Flask session cookie, if attacker knows or guesses `SECRET_KEY` | Secret key is static, low entropy, committed in source | Flask sessions are client-side signed. With the secret, an attacker can forge session values such as `user`, `role`, `student_id`, and `courses`. Current sensitive endpoints mostly lack checks, but any present or future session-based checks would be bypassable | Use the known secret value `dev-secret-key` in a controlled test to generate a Flask session cookie with `role=admin`, then request `/me` and observe accepted session contents | High |
| F-06 | Plaintext demo credentials stored in source | `USERS`, lines 36–43 | Not direct request input; source/config exposure reveals passwords | Passwords are stored and compared in plaintext | If source is exposed, especially through F-04, account credentials are immediately disclosed. Reuse outside the demo environment would increase impact | Read the source file in the deployment environment, or combine with F-04 to attempt to retrieve the application file, and verify plaintext passwords are present | High for code fact; impact depends on deployment/source exposure |
| F-07 | Debug server exposed on all interfaces when run directly | `app.run(debug=True, host="0.0.0.0", port=5001)`, line 160 | Remote HTTP requests to a directly-run Flask dev server | Debug mode and development server are enabled for network exposure | If this file is run directly in an environment reachable by users, Flask/Werkzeug debugger exposure can disclose sensitive details and may enable code execution depending on debugger accessibility and configuration | Start the app exactly via this entry point in a test environment, trigger an exception, and check whether debug behaviour or debugger resources are reachable remotely | Medium-high |
| F-08 | Exception handler leaks internal error details | `handle_error`, lines 151–156; triggered by multiple endpoints | Malformed path/JSON/query inputs causing exceptions, e.g. invalid `student_id`, missing JSON keys, missing file | Generic exception handler returns `str(exc)` and exception class to clients | Attackers can learn implementation details, filesystem paths, missing keys, type errors, and other internals. It also converts many failures into 500 responses | Request `/grades/not-an-int`, POST malformed JSON to `/grades/update`, or request a missing file via `/files`, then inspect returned `error` and `type` | High |
| F-09 | Missing schema and value validation for grade updates | `update_grade`, lines 131–143 | JSON fields `student_id`, `course_id`, `grade` directly used in records | No type checks, required-field handling, grade bounds, course existence, or student existence validation | Attackers can insert inconsistent records, non-existent students/courses, invalid grades, or incompatible types that corrupt the in-memory dataset or break later logic | POST bodies with missing keys, string `student_id`, non-existent `course_id`, or grade values such as `-999`, `"A+"`, or `999` and inspect stored data/responses | High |
| F-10 | Session-cookie API lacks visible CSRF protection for state-changing routes | `login`, `logout`, `update_grade`, lines 82–101 and 129–143 | Browser-submitted cross-site requests carrying victim cookies | No CSRF token or same-site strategy visible in source | If this API is used from browsers with cookie-based sessions, cross-site requests may trigger logout or state changes. The grade update issue is already worse because it lacks auth entirely | In a browser-based test, authenticate, then submit a cross-site form/request to `/logout`; for `/grades/update`, test only if content type/CORS/browser constraints permit JSON submission | Medium; depends on browser deployment assumptions |

## Supporting explanations

### F-01 and F-02: profile and grade IDOR-style read access

The code fact is straightforward: neither `get_profile` nor `get_grades` checks whether a user is logged in.

```python
@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    ...
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)
```

The inferred security requirement is that student profiles and grades are not public. The prompt describes student identifiers, profiles, roles, assigned professor courses, and grade records. In an academic-services API, it is reasonable to assume:

- a student should usually only read their own profile and grades;
- a professor should usually only read students/grades for assigned courses;
- an administrator may have broader access.

If the intended teaching policy is instead “all records are public,” then the confidentiality impact would not hold. The missing control remains demonstrable: there is no authentication or authorisation gate.

### F-03: grade updates are completely unauthenticated

`update_grade` accepts JSON and mutates the global `GRADES` list.

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
```

There is no check for:

- `flask.session["user"]`;
- `flask.session["role"]`;
- whether the actor is a professor;
- whether the professor is assigned to `course_id`;
- whether the student/course pair is valid;
- whether `grade` is in an allowed range.

The prompt states that users have roles and professors have assigned courses. That strongly suggests grade update permissions should be role- and course-scoped. As written, a non-logged-in requester can change any grade.

### F-04: file download path traversal

The vulnerable data flow is:

```python
raw_path = flask.request.args.get("path", "")
target = MATERIALS_DIR / raw_path
return flask.send_file(target)
```

`raw_path` is fully attacker-controlled. Joining it to `MATERIALS_DIR` does not, by itself, guarantee that the resulting path remains inside `MATERIALS_DIR`.

Examples of unsafe path forms include:

- relative traversal such as `../app.py`;
- nested traversal such as `../../some/file`;
- platform-specific absolute paths.

The intended requirement is inferred from the prompt: teaching materials are stored in the application’s materials directory, so downloads should be restricted to that directory. The code does not enforce that.

Potential impact includes reading:

- application source;
- hardcoded credentials;
- configuration files;
- local files readable by the process.

### F-05: hardcoded Flask secret key

The code sets:

```python
app.config["SECRET_KEY"] = "dev-secret-key"
```

Flask’s default session mechanism stores session data client-side in a signed cookie. The signature prevents tampering only if the secret is unknown and sufficiently strong.

This application stores security-relevant identity data in the session:

```python
flask.session["user"] = user.username
flask.session["role"] = user.role
flask.session["student_id"] = user.student_id
flask.session["courses"] = user.courses or []
```

As a demonstrated fact, the secret is static and predictable. As an inferred impact, if an attacker knows the source or guesses the key, they can forge accepted session cookies. In the current code, most sensitive endpoints do not even check the session, but `/me` would reflect forged values, and any future authorisation based on these session fields would be bypassable.

This finding is especially relevant because F-04 may allow source disclosure, which would reveal the key.

### F-06: plaintext credentials in source

The in-memory user records contain plaintext passwords:

```python
USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    ...
}
```

The code compares directly:

```python
if user is None or user.password != password:
```

In a constrained teaching dataset this may be intentional, but the security property is clear: password secrecy depends entirely on source/config secrecy. If application source is exposed, credentials are immediately usable.

This is not necessarily a production-grade finding if the explicit teaching policy permits demo credentials. It becomes more severe if the same pattern is reused outside the demo or if combined with arbitrary file read.

### F-07: debug server exposed on all interfaces

The entry point runs:

```python
app.run(debug=True, host="0.0.0.0", port=5001)
```

This only applies if the application is started by executing this file directly. If deployed through a production WSGI server that ignores this block, the finding does not apply to runtime exposure.

The demonstrated code fact is that direct execution starts Flask with:

- debug mode enabled;
- listening on all network interfaces.

The security concern is that debug servers are not intended for untrusted networks. A confirmation test should inspect whether debug responses or debugger resources are reachable from another host in the same environment.

### F-08: internal error disclosure

The global exception handler returns exception strings and class names to the client:

```python
@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500
```

Several attacker-controlled inputs can trigger exceptions:

- `/grades/not-an-int` → `ValueError`;
- `/students/not-an-int/profile` → `ValueError`;
- `/grades/update` with missing JSON or missing keys → `TypeError` or `KeyError`;
- `/files?path=missing.txt` → file-related exception.

Impact is mainly information disclosure and reconnaissance. Depending on exception messages, this may reveal paths, framework behaviour, parameter names, and implementation details.

One additional behavioural issue: a broad `Exception` handler may also interfere with Flask’s normal HTTP errors, causing client errors to be returned as `500` with internal details.

### F-09: grade update accepts arbitrary data

Beyond the missing authorisation, `update_grade` trusts all submitted values:

```python
student_id = data["student_id"]
course_id = data["course_id"]
grade = data["grade"]
```

There is no validation that:

- `data` is a JSON object;
- all fields exist;
- `student_id` is an integer;
- `student_id` exists in `STUDENT_PROFILES`;
- `course_id` is a known course;
- `grade` is numeric;
- `grade` is within the institution’s allowed range.

The exact valid grade range is not specified in the prompt, so any range requirement is an assumption. However, some validation requirement is strongly implied by the existence of structured grade records.

The potential impact is data integrity loss in the in-memory records, including records that later code may mishandle because of unexpected types.

### F-10: no visible CSRF protection for cookie-session state changes

The app uses Flask sessions, which are normally cookie-backed, and exposes state-changing POST routes:

```python
@app.post("/login")
@app.post("/logout")
@app.post("/grades/update")
```

There is no CSRF token check in the source. No explicit cookie `SameSite` policy is configured in the provided source either.

This finding depends on deployment and client assumptions:

- If this API is used only by non-browser clients with bearer tokens or similar, CSRF may not apply.
- If browser users authenticate with session cookies, cross-site requests can matter.
- `/logout` is easiest to test with a simple cross-site form.
- `/grades/update` uses JSON, so browser mechanics, content type, and CORS behaviour affect exploitability.

This is therefore lower-confidence than the direct unauthenticated grade update issue.

## Overall assessment

The most severe demonstrated issues are:

1. anyone can modify grades;
2. anyone can read grades and profiles, assuming academic records are intended to be private;
3. `/files` allows path traversal outside the teaching-materials directory;
4. the Flask secret and credentials are hardcoded;
5. debug/error behaviour may expose internals.

The absence of additional findings here should not be treated as proof of safety. This review is limited to the provided source and stated context only.
Line numbers are approximate, based on the pasted single-file source.

## Concise findings table

| ID | Finding | Location | Attacker-controlled input and path | Missing control and root cause | Preconditions and impact | Confirming test | Confidence |
|---|---|---:|---|---|---|---|---|
| F-01 | Unauthenticated access to student profiles | `get_profile`, lines 113–118 | URL path `student_id` → `int(student_id)` → `STUDENT_PROFILES.get(...)` → JSON response | No authentication or authorization check before returning profile data | If profiles are intended to be private, any remote caller can enumerate/read student PII | Without logging in, request `GET /students/1001/profile` and `GET /students/1002/profile` | High, assuming profiles are non-public |
| F-02 | Unauthenticated access to grades | `get_grades`, lines 120–124 | URL path `student_id` → filter `GRADES` → JSON response | No authentication or authorization check before returning grades | If grades are private academic records, any remote caller can read another student’s grades | Without logging in, request `GET /grades/1001` | High, assuming grades are private |
| F-03 | Unauthenticated and unauthorized grade modification | `update_grade`, lines 126–140; `find_grade`, lines 56–60 | JSON body `student_id`, `course_id`, `grade` → `find_grade` → append/update `GRADES` | No login check, role check, course ownership check, or validation of who may modify grades | Any caller can create or overwrite grades for any student/course | Without logging in, `POST /grades/update` with `{"student_id":1001,"course_id":"SRS","grade":20}` then `GET /grades/1001` | High |
| F-04 | Arbitrary file read via path traversal / absolute path | `download_file`, lines 142–146 | Query `path` → `MATERIALS_DIR / raw_path` → `flask.send_file(target)` | No canonicalization and no check that resolved path remains under `MATERIALS_DIR`; absolute paths may override the base path | Attacker can read files readable by the process, including source, config, or OS files | Try `GET /files?path=../app.py` or, on Unix-like systems, `GET /files?path=/etc/passwd` | High |
| F-05 | Hard-coded Flask secret key enables session forgery if source/config leaks | App config line 8; session writes lines 89–92 | Known `SECRET_KEY` → attacker can forge signed Flask session cookie containing `user`, `role`, `student_id`, `courses` | Secret is static and embedded in source; authorization state is stored client-side in signed session | If the same key is used in deployment, attacker can create arbitrary logged-in/admin-looking sessions | Using the known secret, generate a Flask session cookie with `{"user":"admin1","role":"admin"}` and request `/me` | High if deployed as-is; otherwise Medium |
| F-06 | Hard-coded plaintext credentials | `USERS`, lines 36–43 | Source-disclosed usernames/passwords → `/login` | Passwords stored in source as plaintext; no hashing or external secret management | Anyone with source or error/file disclosure can log in as seeded users | Login with `username=admin1&password=adminpw` | High for deployed demo credentials |
| F-07 | Excessive exception disclosure and status normalization to 500 | `handle_error`, lines 148–153; triggered from several endpoints | Malformed path/JSON/input → exception → response includes `str(exc)` and exception class | Global exception handler returns internal error details to clients; catches broad `Exception` | Attackers can learn implementation details, file paths, parsing behavior, and possibly secrets in exception text | Request `GET /students/not-an-int/profile`, `POST /grades/update` with `{}`, or missing/invalid JSON | Medium |
| F-08 | Debug server exposed on all interfaces | `app.run`, line 157 | Direct network access to development server | `debug=True` and `host="0.0.0.0"` in runnable entry point | If executed directly in an accessible environment, debug behavior may expose sensitive diagnostics and interactive debugger risk | Start the app as written and access from another host; trigger an exception | Medium to High, deployment-dependent |
| F-09 | Missing input validation for grade updates | `update_grade`, lines 128–140 | JSON `student_id`, `course_id`, `grade` → in-memory grade record | No schema/type/range validation; assumes required fields and valid values | Attackers can store invalid grades, unexpected types, huge payloads, or arbitrary course IDs | POST `{"student_id":"x","course_id":"","grade":"A+"}` or `{"student_id":1001,"course_id":"SRS","grade":999}` | High for integrity issue |
| F-10 | State-changing endpoints lack CSRF protection | `logout`, lines 96–99; `update_grade`, lines 126–140; `login`, lines 80–94 | Browser-submitted cross-site POST using user’s cookies | No CSRF token/origin check; cookie-based Flask session used | If authentication/authorization is added or session matters, another site could cause logged-in users to submit unwanted requests | Log in, then submit a hidden cross-site form to `/logout` or `/grades/update` | Medium; currently grade update is already unauthenticated |

## Supporting explanations

### F-01 and F-02: unauthenticated read access to student data

Demonstrated code facts:

- `get_profile` reads `student_id` directly from the URL path and returns the matching profile.
- `get_grades` reads `student_id` directly from the URL path and returns all matching grade rows.
- Neither function checks `flask.session`, `role`, `student_id`, or `courses`.

Relevant flow:

```text
GET /students/1001/profile
→ get_profile(student_id="1001")
→ int(student_id)
→ STUDENT_PROFILES.get(1001)
→ jsonify(profile)
```

```text
GET /grades/1001
→ get_grades(student_id="1001")
→ int(student_id)
→ rows = grades for student_id 1001
→ jsonify(rows)
```

Inferred security requirement:

- Student profiles and grades are likely private educational records.
- A reasonable policy would usually require at least authentication, and probably object-level authorization:
  - students may read only their own data;
  - professors may read grades/profiles only for students in their courses;
  - admins may read broader data.

Uncertainty:

- The source does not explicitly define the intended access-control policy.
- If the API is intentionally public demo data, the confidentiality impact would be lower. However, the presence of login/session fields strongly suggests some access control was intended.

### F-03: unauthenticated grade modification

Demonstrated code facts:

- `update_grade` accepts JSON from `flask.request.get_json()`.
- It directly trusts `student_id`, `course_id`, and `grade`.
- It either appends a new grade row or overwrites an existing grade.
- There is no check that the caller is logged in.
- There is no check that the caller is a professor or admin.
- There is no check that a professor teaches the submitted course.

Relevant flow:

```text
POST /grades/update
JSON body:
{
  "student_id": 1001,
  "course_id": "SRS",
  "grade": 20
}

→ update_grade()
→ data = request.get_json()
→ student_id = data["student_id"]
→ course_id = data["course_id"]
→ grade = data["grade"]
→ find_grade(student_id, course_id)
→ row["grade"] = grade
```

Potential impact:

- Anyone can change Alice’s or Bob’s grades.
- Anyone can create new grade entries for arbitrary students and courses.
- A student could modify their own grades or another student’s grades.
- An unauthenticated external user could do the same.

This is the highest-impact issue in the code because it affects integrity directly and does not require any prior compromise.

### F-04: arbitrary file read

Demonstrated code facts:

```python
raw_path = flask.request.args.get("path", "")
target = MATERIALS_DIR / raw_path
return flask.send_file(target)
```

The code joins attacker-controlled `raw_path` to `MATERIALS_DIR`, but it does not:

- reject `..` path segments;
- reject absolute paths;
- resolve the canonical path;
- verify the final path is still inside `MATERIALS_DIR`;
- restrict downloads to an allowlist of known material files.

Relevant flow:

```text
GET /files?path=../app.py
→ raw_path = "../app.py"
→ target = MATERIALS_DIR / "../app.py"
→ send_file(target)
```

Depending on the filesystem layout, `../app.py` could resolve to the application source file. On Unix-like systems, an absolute path such as `/etc/passwd` may also cause the right-hand absolute path to override the base directory when using `pathlib`.

Potential impact:

- disclosure of application source;
- disclosure of credentials in source;
- disclosure of config files;
- disclosure of local files readable by the Flask process;
- possible disclosure of the hard-coded `SECRET_KEY`, making session forgery easier.

The most direct confirming tests are:

```text
GET /files?path=srs-summary.txt
GET /files?path=../app.py
GET /files?path=/etc/passwd
```

A valid security control would need to ensure the served file is actually inside the intended materials directory, but no patch is provided here per request.

### F-05: hard-coded secret key and client-side session trust

Demonstrated code facts:

```python
app.config["SECRET_KEY"] = "dev-secret-key"
```

The app then stores identity and authorization-relevant data in the Flask session:

```python
flask.session["user"] = user.username
flask.session["role"] = user.role
flask.session["student_id"] = user.student_id
flask.session["courses"] = user.courses or []
```

In Flask’s default session model, session data is stored client-side in a signed cookie. The signature prevents tampering only if the secret key is unknown and sufficiently strong.

Root cause:

- The signing key is hard-coded and predictable.
- Authorization-relevant state is placed in the client-side session.
- If deployed with this exact key, anyone who knows the source can mint valid session cookies.

Potential impact:

- A forged session could make `/me` report the attacker as `admin1`.
- If future or external code trusts `session["role"]`, this could become full authorization bypass.
- Combined with the file-read issue, an attacker may be able to retrieve the source and learn the secret key even without repository access.

Current-code nuance:

- The most sensitive endpoints currently do not check the session at all, so session forgery is not required to exploit grade/profile issues.
- The risk becomes especially important if access checks are later added but continue trusting the same weak session secret.

### F-06: hard-coded plaintext credentials

Demonstrated code facts:

```python
USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(username="prof_srs", password="profpw", role="professor", courses=["SRS"]),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}
```

And login checks plaintext directly:

```python
if user is None or user.password != password:
    return {"error": "invalid credentials"}, 401
```

Root cause:

- Passwords are stored directly in source.
- Passwords are stored in plaintext rather than using a password hashing scheme.
- Demo credentials include an admin account.

Potential impact:

- Anyone with source access can authenticate.
- If `/files` can read the source file, unauthenticated users may recover the credentials.
- If reused elsewhere, these credentials could enable broader compromise.

Uncertainty:

- This may be intentional demo data. If so, the risk depends on whether the app is deployed beyond a local exercise environment.

### F-07: exception disclosure

Demonstrated code facts:

```python
@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500
```

Several endpoints can trigger exceptions using attacker-controlled input:

```text
GET /students/not-an-int/profile
→ int("not-an-int")
→ ValueError
→ error response includes exception text and class
```

```text
POST /grades/update
Body: {}
→ data["student_id"]
→ KeyError
→ error response includes exception text and class
```

```text
GET /files?path=missing.txt
→ send_file(...)
→ file-not-found exception
→ error response may disclose filesystem details
```

Root cause:

- Broad global exception handling.
- Internal exception messages returned directly to the client.
- All exceptions normalized to HTTP 500, including likely client errors or routing errors.

Potential impact:

- Information disclosure.
- Easier endpoint mapping and exploit development.
- Possible filesystem path disclosure through file-serving errors.
- Noisy behavior that may hide proper 404/400/403 distinctions.

### F-08: debug mode exposed on all interfaces

Demonstrated code fact:

```python
app.run(debug=True, host="0.0.0.0", port=5001)
```

Root cause:

- Development server configuration is embedded in the application entry point.
- Debug mode is enabled.
- Binding to `0.0.0.0` exposes it on all network interfaces when run directly.

Potential impact:

- Sensitive debug diagnostics may be exposed.
- In some Flask/Werkzeug debug configurations, an interactive debugger can become a serious remote code execution risk if reachable and bypassed.
- Attackers can combine this with deliberate exception triggering.

Uncertainty:

- This applies when the file is executed directly.
- If deployed behind a production WSGI server that does not run this block, the direct impact is reduced.
- The source alone does not show the deployment method.

### F-09: missing validation for grade update data

Demonstrated code facts:

```python
data = flask.request.get_json()

student_id = data["student_id"]
course_id = data["course_id"]
grade = data["grade"]
```

No checks are performed for:

- JSON body presence;
- required field existence;
- type of `student_id`;
- type or allowed values of `course_id`;
- type/range of `grade`;
- grade scale;
- course existence;
- student existence.

Relevant test cases:

```json
{"student_id":1001,"course_id":"SRS","grade":999}
```

```json
{"student_id":"1001","course_id":"SRS","grade":"excellent"}
```

```json
{"student_id":1001,"course_id":"","grade":null}
```

Potential impact:

- Corrupted grade records.
- Duplicate logical records due to type mismatch, for example integer `1001` versus string `"1001"`.
- Unexpected downstream errors if later code assumes numeric grades.
- Abuse through large payloads or malformed values.

This is both a security and data-integrity issue. Its severity depends on whether the API is reachable by untrusted users; in this source, it is reachable without authentication.

### F-10: missing CSRF protection

Demonstrated code facts:

- The app uses Flask sessions, which are normally cookie-based.
- State-changing endpoints exist:
  - `POST /login`
  - `POST /logout`
  - `POST /grades/update`
- There is no visible CSRF token validation, Origin validation, or SameSite configuration.

Current-code nuance:

- `POST /grades/update` does not require authentication, so CSRF is not needed to exploit it; direct unauthenticated requests already work.
- `POST /logout` can be CSRF-relevant because it changes the victim’s session state.
- If authentication and authorization are later added to grade updates without CSRF protection, a malicious site could cause a logged-in professor/admin browser to submit grade changes.

Inferred requirement:

- CSRF protection is relevant if the API is intended to be called from browsers using cookie-based authentication.

## Overall observations

The main demonstrated risks are broken access control, arbitrary file read, and unsafe deployment/configuration defaults. The most critical issue is that grade modification is fully unauthenticated. The file download endpoint can also expose the application source, which would reveal the hard-coded secret key and credentials.

The review is limited to the provided source. It does not prove the absence of other vulnerabilities in dependencies, deployment configuration, reverse proxies, templates, databases, or code not included here.

# JWT-Risk-Auth

JWT-Risk-Auth is a FastAPI project for reproducing and extending a behavior-aware JWT authentication method. It starts from the idea in *Enhancing JWT Authentication and Authorization in Web Applications Based on User Behavior History*: login should not depend only on a password check, because the login context also says something about whether the request looks normal.

The project keeps the original paper-style decision flow as a baseline, then adds a small risk scoring model that considers failed attempts, IP changes, device changes, login time, token-related events, and recent abnormal behavior. 

## What it is

- A runnable FastAPI backend for user registration, login, challenge verification, and JWT issuance.
- A reproduction of the original credibility-based JWT login decision.
- An improved risk-scoring mode with `allow`, `challenge`, and `deny` outcomes.
- A set of experiment scripts for simulated login events and method comparison.
- A test suite that checks the authentication flow, JWT handling, scoring logic, and experiment outputs.

## What is implemented

- Email-based registration with hashed passwords and an initialized authentication profile.
- Login with password verification, client IP/User-Agent capture, login event persistence, and JWT session records.
- Original mode: percentage-based credibility from failed attempts, IP consistency, and User-Agent consistency.
- Improved mode: weighted risk scoring over multiple behavior and context factors.
- Low-credibility challenge flow with one-time challenge verification and short-lived challenge JWTs.
- Local mail fallback for development, so the challenge flow can be tested without a real SMTP account.

## Stack

- Python 3.11+
- FastAPI
- SQLAlchemy 2.0
- Alembic
- PostgreSQL
- PyJWT
- pytest
- pandas and matplotlib
- Docker Compose

## Project layout

```text
JWT-Risk-Auth
├─ app
│  ├─ api/v1              # API routes
│  ├─ core                # settings and security helpers
│  ├─ db                  # database session setup
│  ├─ models              # SQLAlchemy models
│  ├─ schemas             # Pydantic schemas
│  └─ services            # auth, JWT, mail, challenge, and scoring services
├─ alembic                # database migrations
├─ experiments            # simulated data and comparison scripts
├─ tests                  # automated tests
├─ .env.example           # local configuration template
├─ docker-compose.yml     # PostgreSQL for local development
└─ requirements.txt
```

## Run locally

Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

The default configuration is for local development. Change the values in `.env` when you need a different database URL, JWT secret, or SMTP account.

Start PostgreSQL and apply migrations:

```powershell
docker compose up -d
alembic upgrade head
```

Start the API:

```powershell
uvicorn app.main:app --reload
```

Useful local URLs:

- Swagger UI: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

## Authentication modes

`AUTH_DECISION_MODE` controls the login decision strategy:

```env
AUTH_DECISION_MODE=original
```

- `original` keeps the reproduced credibility method as the login decision.
- `improved` uses the risk scoring service and can return `allow`, `challenge`, or `deny`.

The improved score is calculated from a 0-100 risk scale. Scores up to 30 are allowed, scores from 31 to 70 trigger a challenge, and scores above 70 are denied.

## API endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Service health check |
| `POST` | `/api/v1/users/register` | Register a user |
| `POST` | `/api/v1/auth/login` | Login and receive either a JWT or challenge options |
| `POST` | `/api/v1/auth/challenge/verify` | Verify a challenge and receive a short-lived JWT |

## Experiments

Generate simulated login events:

```powershell
python experiments/generate_simulated_data.py
```

Compare the original and improved methods:

```powershell
python experiments/run_comparison.py
```

Generate plots:

```powershell
python experiments/plot_results.py
```

The default experiment covers five scenarios:

- `normal`
- `network_change`
- `password_attack`
- `new_device`
- `token_replay`

Generated CSV and PNG files are ignored by Git so the repository stays focused on code.

## Tests

Run the test suite with:

```powershell
pytest
```

The tests cover registration, duplicate email handling, password errors, challenge success/failure cases, original and improved login decisions, JWT creation, scoring behavior, and experiment output generation.

## Status

The repository currently focuses on login-time authentication decisions and experiment reproduction. Token replay is modeled in the experiment data and scoring fields, but full token lifecycle governance is not implemented yet. Refresh token rotation, logout, denylist/state checks, and sender-constrained tokens are left as future work.

The generated experiment data is simulated and does not contain real user behavior logs.

## License

Released under the MIT License.

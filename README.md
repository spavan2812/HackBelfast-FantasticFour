# CyberPath

**AI-powered cyber insurance risk assessment for Belfast SMEs.**
Adaptive questionnaire driven by a local Ollama LLM → instant risk score → locked report unlocked via lead capture.

---

## What it does

1. **Onboarding** — collects company profile (name, industry, size, certifications, asset footprint) across 4 steps
2. **Adaptive assessment** — Ollama picks the next most relevant question from a 100-question bank until enough signal is gathered
3. **Partial results** — risk score (0–100) and category breakdown are shown immediately
4. **Lead capture** — full narrative report, gap analysis and recommendations unlock after the user provides their email; a thank-you email is sent automatically
5. **Upload evidence** — users can attach certification documents, audit reports, pen test results as supporting proof

---

## Running with Docker (recommended)

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose v2)
- ~6 GB free disk space for the llama3 model weights

### First-time setup

```bash
git clone https://github.com/your-org/HackBelfast-FantasticFour.git
cd HackBelfast-FantasticFour

make setup
```

`make setup` will:

1. Build the Flask app image
2. Start the Ollama service
3. Pull `llama3:latest` into the Ollama container (~4 GB, one-time download)
4. Start the app at `http://localhost:5000`

### Subsequent runs

```bash
make up        # start all containers
make down      # stop all containers
make restart   # rebuild app image only (Ollama untouched)
make logs      # stream app logs
make shell     # open a shell inside the app container
```

### Email configuration (optional)

Copy `.env.example` to `.env` and fill in your SMTP credentials.
If omitted, lead capture emails are logged to the console instead.

```bash
cp .env.example .env
```

```ini
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USER=your@email.com
MAIL_PASS=your-app-password
MAIL_FROM=hello@cyberpath.io
```

---

## Running locally (without Docker)

### Local prerequisites

- Python 3.14
- [Ollama](https://ollama.com) installed and running locally

### Local setup

```bash
# 1. Clone and enter the project
git clone https://github.com/your-org/HackBelfast-FantasticFour.git
cd HackBelfast-FantasticFour

# 2. Create and activate a virtual environment
python3 -m venv env
source env/bin/activate        # Windows: env\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Pull the LLM model (one-time, ~4 GB)
ollama pull llama3:latest

# 5. Start Ollama if it is not already running as a background service
ollama serve &

# 6. Run the app
flask --app app run --debug
```

App available at `http://localhost:5000`.

---

## Project structure

```text
HackBelfast-FantasticFour/
├── app/
│   ├── __init__.py          # Flask app factory, CORS setup
│   ├── routes.py            # All API endpoints
│   ├── static/
│   │   └── uploads/         # Uploaded proof documents
│   └── templates/
│       └── index.html       # Full single-page application
├── logic/
│   └── questions.json       # 100-question risk assessment bank
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── requirements.txt
└── run.py
```

---

## API endpoints

| Method | Path                              | Description                              |
|--------|-----------------------------------|------------------------------------------|
| `GET`  | `/api/models`                     | List available Ollama models             |
| `POST` | `/api/assessment/next-question`   | Get the next adaptive question           |
| `POST` | `/api/assessment/report`          | Generate scored report + narrative       |
| `POST` | `/api/lead/capture`               | Save lead and send thank-you email       |
| `POST` | `/api/upload`                     | Upload supporting evidence files         |
| `POST` | `/api/chat`                       | Generic Ollama chat proxy (SSE stream)   |

### Example — next-question

```bash
curl -X POST http://localhost:5000/api/assessment/next-question \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3:latest",
    "answers": {
      "CTX_001": "saas",
      "CTX_002": "11-50",
      "RAN_001": "3_2_1"
    }
  }'
```

### Example — generate report

```bash
curl -X POST http://localhost:5000/api/assessment/report \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3:latest",
    "answers": { "RAN_001": "no", "DATA_001": "none" },
    "context": { "industry": "saas", "companySize": "11-50" }
  }'
```

---

## Tech stack

| Layer            | Technology                                       |
|------------------|--------------------------------------------------|
| Backend          | Python 3.14, Flask 3.0, Gunicorn                 |
| LLM              | Ollama (`llama3:latest`)                         |
| Frontend         | Vanilla JS + Tailwind CSS (CDN), served by Flask |
| Containerisation | Docker + Docker Compose                          |
| Email            | Python `smtplib` (SMTP, configurable via env)    |

---

Built for **HackBelfast 2026** by Fantastic Four.

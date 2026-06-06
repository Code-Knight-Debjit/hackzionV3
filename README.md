# 🛡️ CyberGuard — AI-Powered Cyber Deception & Threat Intelligence Platform

> A full-stack, Dockerized cybersecurity research platform that combines honeypot deception, real-time AI threat analysis, CVSS scoring, MITRE ATT&CK mapping, and a live mobile monitoring dashboard — all working together as a single self-contained system.

---

## 📖 Table of Contents

1. [What Is CyberGuard?](#-what-is-cyberguard)
2. [How the System Works — The Big Picture](#-how-the-system-works--the-big-picture)
3. [Architecture Diagram](#-architecture-diagram)
4. [Folder-by-Folder Breakdown](#-folder-by-folder-breakdown)
   - [proxy](#-proxy--the-front-door)
   - [gateway](#-gateway--the-brain-of-routing)
   - [backend](#-backend--the-real-application)
   - [honeypot](#-honeypot--the-trap)
   - [detection](#-detection--the-analyst)
   - [response](#-response--the-enforcer)
   - [ai_analyzer](#-ai_analyzer--the-intelligence-engine)
   - [api](#-api--the-data-broker)
   - [database](#-database--persistent-storage)
   - [monitorapp](#-monitorapp--the-command-center)
   - [simulator](#-simulator--the-attacker-emulator)
   - [logs](#-logs--audit-trail)
   - [dummy_site](#-dummy_site--the-bait-facade)
5. [How Folders Affect Each Other — The Data Flow](#-how-folders-affect-each-other--the-data-flow)
6. [Key Technologies Used](#-key-technologies-used)
7. [Infrastructure: docker-compose.yml](#-infrastructure-docker-composeyml)
8. [Getting Started](#-getting-started)
9. [Why Each Component Matters](#-why-each-component-matters)

---

## 🧠 What Is CyberGuard?

CyberGuard is a **cyber deception and threat intelligence system** — a platform that intentionally lures attackers, studies their behavior in real-time, classifies their attacks with AI, and responds automatically. It is the third major version of the Hackzion project.

Instead of simply blocking attackers (which tells them nothing and only slows them down), CyberGuard **silently redirects** malicious traffic to a fake environment (a honeypot) that looks like a real vulnerable application. While the attacker thinks they are exploiting a real system, every action they take is captured, scored by severity, classified by attack type, mapped to MITRE ATT&CK techniques, and stored in a database — all in real time.

The system is:
- **Fully containerized** using Docker Compose — spin up the entire platform with one command.
- **AI-powered** — uses a locally-running LLM (Llama3 via Ollama) to analyze and classify attacks.
- **Observable** — includes a React Native mobile monitoring app for live attack dashboards.
- **Self-defending** — automatically escalates suspicious IPs and triggers response actions.

---

## 🔄 How the System Works — The Big Picture

Every incoming HTTP request to the system goes through a carefully designed pipeline:

```
Internet
   │
   ▼
[proxy]          ← Nginx. Public-facing entry point. Routes all traffic inward.
   │
   ▼
[gateway]        ← FastAPI. Scores each request. Decides: real user or attacker?
   │                Risk Engine reads IP history, behavior signals, and patterns.
   ├──── score < threshold ──────────────────────────────────────► [backend]
   │                                                               Real app. Serves legit users.
   └──── score ≥ threshold ──────────────────────────────────────► [honeypot]
                                                                   Fake app. Traps attackers.
                                                                        │
                                                                        ▼
                                                                   [detection]    ← Analyzes the captured request.
                                                                        │           ML model + MITRE mapper + behavior.
                                                                        ▼
                                                                   [response]     ← Decides what action to take.
                                                                        │           Escalate IP? Alert? Block?
                                                                        ▼
                                                                   [ai_analyzer]  ← LLM pipeline. Full CVSS scoring.
                                                                        │           Writes final report to MongoDB.
                                                                        ▼
                                                                   [MongoDB]      ← Stores all attack intelligence.
                                                                        │
                                                                        ▼
                                                                   [api] ──────► [monitorapp]
                                                                                  Mobile dashboard.
                                                                                  Live attack feed.
```

---

## 🗺️ Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Docker Network: hackzion_net                      │
│                                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │  proxy   │───►│ gateway  │───►│ backend  │    │    honeypot      │  │
│  │ (Nginx)  │    │ :8000    │    │  :9000   │    │     :9001        │  │
│  │  :80     │    │ FastAPI  │    │ FastAPI  │    │  FastAPI + LLM   │  │
│  └──────────┘    └──────────┘    └──────────┘    └────────┬─────────┘  │
│                       │                                    │            │
│                       │                          ┌─────────▼─────────┐  │
│                       │                          │    detection      │  │
│                       │                          │     :8001         │  │
│                       │                          │  ML + MITRE map   │  │
│                       │                          └─────────┬─────────┘  │
│                       │                                    │            │
│                       │                          ┌─────────▼─────────┐  │
│                       │                          │     response      │  │
│                       │                          │     :8002         │  │
│                       │                          │  Actions engine   │  │
│                       │                          └─────────┬─────────┘  │
│                       │                                    │            │
│                       │                          ┌─────────▼─────────┐  │
│                       │                          │   ai_analyzer     │  │
│                       │                          │     :8004         │  │
│                       │                          │  LLM + CVSS +     │  │
│                       │                          │  Threat Intel     │  │
│                       │                          └──────┬────────────┘  │
│                       │                                 │               │
│                  ┌────▼────┐              ┌────────────▼──────────┐    │
│                  │   api   │              │       MongoDB         │    │
│                  │  :8003  │◄────────────►│  Attack Intelligence  │    │
│                  └────┬────┘              │       Store           │    │
│                       │                  └───────────────────────┘    │
│                       │                                                 │
│                  ┌────▼────────┐         ┌───────────────────────┐    │
│                  │ monitorapp  │         │       Ollama           │    │
│                  │ React Native│         │  Llama3 LLM :11434    │    │
│                  │ Dashboard   │         └───────────────────────┘    │
│                  └─────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Folder-by-Folder Breakdown

---

### 🚪 `proxy/` — The Front Door

**What it is:** An Nginx reverse proxy that sits at port 80, the only publicly exposed port.

**Why it matters:** In any serious production or research deployment, you never expose internal services directly to the internet. The proxy acts as the single entry point, handing all traffic off to the `gateway` service internally. This means:
- External attackers never know how many services are running behind it.
- SSL termination can be added here without touching any application code.
- Rate limiting and basic DDoS protection can be configured at this layer.

**How it connects:** `proxy → gateway`. The proxy blindly forwards every request to the gateway on the internal Docker network.

---

### 🧠 `gateway/` — The Brain of Routing

**What it is:** A FastAPI application that acts as an intelligent reverse proxy and traffic classifier. This is the most critical folder in the entire project.

**Key files:**
- `router.py` — The catch-all route handler. Reads a `risk_decision` from middleware and routes the request to either the real `backend` or the `honeypot`.
- `risk_engine.py` (implied) — Maintains an in-memory score store for each IP. Computes a risk score based on behavioral signals. Manages escalation logic.

**How routing decisions work:**
1. Every incoming request goes through middleware that scores the IP.
2. If the score is below the threshold → marked as `"real"` → forwarded to `backend`.
3. If the score meets or exceeds the threshold → marked as `"honeypot"` → forwarded to the honeypot.
4. A third state `"monitor"` sends traffic to the real backend but flags it for extra observation.
5. When traffic is routed to the honeypot, the gateway simultaneously fires a side-call to `detection` and `response` to analyze and act on the attack.

**Why it matters:** This is what makes the system "deceptive." The attacker never receives an error or a block — they get a convincing fake response that keeps them engaged while the system studies them.

**Routing headers added to every forwarded request:**
- `X-Route-Decision` — `real`, `honeypot`, or `monitor`
- `X-Risk-Score` — the numeric score assigned to the IP
- `X-Client-IP` — the original attacker IP

**How it connects:**
- Receives from: `proxy`
- Sends to: `backend` (legit traffic), `honeypot` (attacker traffic)
- Also calls: `detection` and `response` for honeypot-routed requests
- Exposes `/api/attacks`, `/api/alerts`, `/api/stats` as proxy passthrough endpoints for `monitorapp`

---

### 🏢 `backend/` — The Real Application

**What it is:** A FastAPI service running on port 9000 that serves the actual (real) application. Legitimate users interact with this.

**Why it matters:** In a real deployment, this would be your production application. In CyberGuard's research context, it serves as the "clean" destination — the one that real users (or lower-risk IPs) reach. It also receives `"monitor"`-flagged traffic so that borderline users can be observed without disrupting their experience.

**How it connects:**
- Receives from: `gateway` (for `"real"` and `"monitor"` decisions)
- No outbound calls — it is a destination, not a caller.

---

### 🍯 `honeypot/` — The Trap

**What it is:** A FastAPI application designed to look like a vulnerable real application. Running on port 9001, it intercepts attacker traffic and produces realistic-looking fake responses.

**Key files:**
- `main.py` — The honeypot's FastAPI app. Accepts all HTTP methods across all paths.
- `fake_vuln_handler.py` — Returns convincing fake vulnerability responses. When an attacker tries a SQL injection, this returns a fake database error. When they try path traversal, it pretends the file was found. The goal is to keep them engaged.
- `ai_engine.py` — A local AI engine that can generate dynamic, contextually appropriate fake responses.
- `ai_handler.py` — Bridges the honeypot to the `ai_analyzer` service. After every trapped request, it calls `ai_analyzer/analyze/async` to trigger the full AI pipeline in the background.

**Why it matters:** A honeypot is only valuable if it's convincing. Real attackers use automated scanners and manual probing. If the honeypot immediately returns errors or inconsistent responses, they move on. `fake_vuln_handler.py` ensures that the bait is believable enough to keep them probing — giving the system more data to study.

**Every time a request hits the honeypot:**
1. A realistic fake response is returned to the attacker.
2. In the background, `ai_handler.py` fires a POST to `ai_analyzer:8004/analyze/async` with the full request metadata.
3. The attacker sees nothing unusual — they think they're making progress.

**How it connects:**
- Receives from: `gateway` (attacker traffic)
- Calls: `ai_analyzer` (to log and analyze every attack)

---

### 🔬 `detection/` — The Analyst

**What it is:** A FastAPI microservice on port 8001 that receives captured attack data and performs multi-layered analysis.

**Key files:**
- `main.py` — Entry point. Accepts POST `/analyze` with attack event payloads.
- `ml_model.py` — A machine learning model that classifies the attack type based on request features.
- `behavior_analyzer.py` — Analyzes the behavioral pattern of the attacker: Is this automated scanning? Manual probing? Tool-based exploitation (e.g., sqlmap, nikto)?
- `mitre_mapper.py` — Maps the detected attack pattern to a MITRE ATT&CK technique ID and tactic (e.g., T1190 — Exploit Public-Facing Application).

**Why it matters:** Raw HTTP logs are not actionable intelligence. `detection` transforms a raw request into structured threat data with attack type, behavior profile, and a MITRE technique ID. This enrichment is what makes the data stored in MongoDB actually useful for security analysis rather than just being a pile of logs.

**How it connects:**
- Receives from: `gateway` (called after every honeypot-routed request)
- Sends to: `response` (the analysis result is passed downstream for action)

---

### ⚡ `response/` — The Enforcer

**What it is:** A FastAPI microservice on port 8002 that receives `detection` analysis results and decides what action to take.

**Why it matters:** Detecting a threat is only half the work — the system must also *respond*. The response engine:
- Decides whether to escalate an IP (increase its risk score permanently, locking it to honeypot routing forever)
- Can call back to `gateway`'s `/risk/escalate` endpoint to force-flag an IP
- Can trigger alerts to external systems (configured via `ALERT_API_URL` and `ALERT_API_KEY` environment variables)
- Logs its decisions to SQLite via the shared `db_data` volume

**How it connects:**
- Receives from: `detection` (analysis results)
- Calls: `gateway /risk/escalate` (to permanently escalate dangerous IPs)
- Shares: `db_data` volume with `detection`, `api`, and `honeypot` for SQLite access

---

### 🤖 `ai_analyzer/` — The Intelligence Engine

**What it is:** The most sophisticated folder in the project. A FastAPI service on port 8004 that runs a full AI pipeline on every captured attack. It is powered by a locally-running Llama3 LLM via Ollama and stores results in MongoDB.

**Key files:**
- `main.py` — FastAPI app. Exposes `/analyze`, `/analyze/async`, `/attacks`, `/profiles`, `/stats`, `/logs`.
- `analyzer.py` — Orchestrates the full pipeline: LLM classification → CVSS scoring → Threat Intel matching → Profiler update → MongoDB write.
- `cvss_engine.py` — Computes a CVSS (Common Vulnerability Scoring System) score for the attack based on its characteristics. CVSS is the industry-standard scoring system used by security professionals worldwide.
- `threat_intel.py` — Matches the attack against known threat signatures and patterns. Determines OWASP category, matched signatures, and mitigations.
- `profiler.py` — Builds and updates a "threat actor profile" for each unique attacker IP. Over time, repeated attacks from the same IP accumulate into a behavioral profile.
- `database.py` — Async MongoDB interface using Motor. Writes attack records and reads them back for the API.
- `api_client.py` — HTTP client used to send alerts to external webhook systems.

**The full analysis pipeline (triggered per attack):**
```
Raw attack log
     │
     ▼
LLM (Llama3) classifies attack type, extracts intent, determines confidence
     │
     ▼
CVSS Engine scores the attack (Low / Medium / High / Critical)
     │
     ▼
Threat Intel matches against known signatures, OWASP, MITRE
     │
     ▼
Profiler updates the IP's behavioral profile in MongoDB
     │
     ▼
Full report written to MongoDB `attack_logs` collection
     │
     ▼
Optional: alert fired to external webhook
```

**The `/attacks` endpoint** is the live feed that `monitorapp` polls. Every attack ever recorded appears here, with full enrichment: CVSS score, attack type, behavior, MITRE technique, OWASP category, mitigation advice, LLM confidence, and more.

**Why it matters:** This is what elevates CyberGuard from a basic honeypot logger to an actual threat intelligence platform. The combination of LLM + CVSS + MITRE + OWASP produces reports that are directly useful for security research, report writing, and incident documentation.

**How it connects:**
- Receives from: `honeypot` (via `ai_handler.py`), `gateway` (via `/api/attacks` passthrough)
- Calls: `Ollama` (local LLM), `MongoDB` (storage)
- Serves: `api`, `monitorapp`, `gateway` (read endpoints)

---

### 🔌 `api/` — The Data Broker

**What it is:** A FastAPI microservice on port 8003 that provides a structured API for querying attack data. Acts as a clean interface layer between the raw data stores and the monitoring frontend.

**Key endpoints (proxied through gateway):**
- `GET /api/attacks` — All attack sessions
- `GET /api/attacks/{session_id}` — Single session detail
- `GET /api/alerts` — Generated alerts
- `POST /api/action/block` — Manually block an IP
- `GET /api/stats` — Aggregate statistics

**Why it matters:** Rather than letting `monitorapp` directly call `ai_analyzer` or the SQLite database, the `api` service provides a stable, versioned, access-controlled interface. This separation means the storage layer can change (e.g., switching databases) without breaking the mobile app.

**How it connects:**
- Reads from: `db_data` SQLite volume
- Served through: `gateway` (all `/api/*` routes are proxied)
- Consumed by: `monitorapp`

---

### 💾 `database/` — Persistent Storage

**What it is:** The folder containing database initialization scripts and schema definitions for the SQLite database shared across services.

**Why it matters:** Multiple services (`honeypot`, `detection`, `response`, `api`) share a single SQLite database file via the `db_data` Docker volume mounted at `/data/hackzion.db`. The `database/` folder ensures the schema is initialized correctly before any service tries to write to it.

**Two databases exist in CyberGuard:**
- **SQLite** (`hackzion.db`) — Fast, file-based. Used for operational data: attack sessions, alerts, IP block lists, response actions.
- **MongoDB** (`hackzion` database) — Document store. Used by `ai_analyzer` exclusively for the rich, schema-flexible attack intelligence reports that include LLM output, CVSS vectors, and threat profiles.

**How it connects:** Shared volume dependency for `honeypot`, `detection`, `response`, and `api`.

---

### 📱 `monitorapp/` — The Command Center

**What it is:** A React Native application (using Expo) built as a mobile dashboard for monitoring the CyberGuard system in real time.

**Key files:**
- `App.js` — Root navigation. Wires up the screen stack.
- `src/screens/` — Individual screen components (attack feed, stats, profiles, alerts).
- `nginx.conf` — When built for web deployment, served via Nginx.
- `app.json` — Expo configuration (app name, icons, platform targets).

**What it shows:**
- Live attack feed (polls `gateway /api/attacks/live`)
- Per-attack detail: IP, timestamp, attack type, CVSS severity, MITRE technique, OWASP category, mitigation, LLM confidence
- Threat actor profiles per IP (built up over repeated attacks)
- Aggregate statistics (attack counts by type, severity distribution, top IPs)
- Alert notifications

**Why it matters:** Security research is useless if the data is trapped in a database that only a developer can query. `monitorapp` makes the intelligence accessible in real time, on any device, without needing CLI access to the server. It's also the primary demo interface for showcasing the system.

**How it connects:**
- Calls: `gateway /api/*` endpoints (which proxy to `ai_analyzer` and `api`)
- No direct database access — always goes through the API layer

---

### 🎭 `simulator/` — The Attacker Emulator

**What it is:** A set of scripts that simulate realistic attacker behavior against the system. Used for testing, development, and demonstration.

**Why it matters:** You can't wait for real attackers to show up when developing and testing the system. The `simulator` fires synthetic attacks — SQL injections, path traversal, brute force, XSS, command injection — at the gateway, so all downstream components (`detection`, `ai_analyzer`, `monitorapp`) can be verified end-to-end. It's also invaluable for demos: run the simulator and the `monitorapp` dashboard populates with realistic-looking attack data in seconds.

**How it connects:** Makes HTTP requests directly to the gateway (port 8000), just like a real attacker would. The gateway then routes them through the full pipeline.

---

### 📋 `logs/` — Audit Trail

**What it is:** A directory for persistent log files written by various services.

**Why it matters:** Docker container logs are ephemeral — they disappear when containers are restarted. The `logs/` directory (potentially mounted as a volume) provides a persistent audit trail of system activity. This is important for forensic analysis, debugging, and compliance in a research context.

---

### 🎪 `dummy_site/` — The Bait Facade

**What it is:** A static file or simple web page that the honeypot can serve as its "front page" — making it look like a real website to casual probing.

**Why it matters:** When an attacker first discovers the system, they typically browse to the root URL to see what kind of application it is. If they see a blank page or a 404, they know something is off. `dummy_site` provides convincing visual cover — it looks like a real company website or web application — encouraging the attacker to probe deeper and generate more intelligence data.

**How it connects:** Served by `honeypot` as its default response for non-exploit requests.

---

## 🔗 How Folders Affect Each Other — The Data Flow

Understanding the inter-folder dependencies is key to understanding why the system works as a whole.

### The "Happy Path" (legitimate user)

```
proxy → gateway (score: low) → backend → response to user
```
The gateway scores the IP as low-risk. The request goes to the real backend. No security pipeline triggered.

### The "Trap Path" (attacker)

```
proxy
  → gateway (score: high → decision: "honeypot")
    → honeypot (returns convincing fake response to attacker)
      → ai_handler.py fires async call to ai_analyzer
        → ai_analyzer runs LLM + CVSS + threat_intel + profiler
          → MongoDB stores full enriched attack record
    → gateway simultaneously calls detection
      → detection runs ML model + MITRE mapper + behavior analyzer
        → detection result passed to response
          → response decides: escalate IP score in gateway
```

Meanwhile:

```
monitorapp polls gateway /api/attacks/live
  → gateway proxies to ai_analyzer /attacks
    → ai_analyzer reads from MongoDB
      → live attack feed updates on mobile dashboard
```

### Key cross-folder dependencies

| Folder | Depends On | Depended On By |
|---|---|---|
| `proxy` | `gateway` | External traffic |
| `gateway` | `backend`, `honeypot`, `detection`, `response`, `ai_analyzer` | `proxy`, `monitorapp` |
| `honeypot` | `ai_analyzer` | `gateway` |
| `detection` | `database` (SQLite) | `gateway`, `response` |
| `response` | `database` (SQLite), `gateway` (escalate endpoint) | `detection` |
| `ai_analyzer` | `Ollama` (LLM), `MongoDB` | `honeypot`, `gateway`, `monitorapp` |
| `api` | `database` (SQLite) | `gateway`, `monitorapp` |
| `monitorapp` | `gateway /api/*` | End user / researcher |
| `simulator` | `gateway` | Development & demo |
| `database` | — | `honeypot`, `detection`, `response`, `api` |

---

## 🛠️ Key Technologies Used

| Technology | Role | Where Used |
|---|---|---|
| **FastAPI** | Async Python web framework | `gateway`, `honeypot`, `backend`, `detection`, `response`, `ai_analyzer`, `api` |
| **Nginx** | Reverse proxy & static file server | `proxy`, `monitorapp` |
| **Docker / Docker Compose** | Containerization & orchestration | Root `docker-compose.yml` |
| **Ollama + Llama3** | Local LLM for attack classification | `ai_analyzer` |
| **MongoDB** | Document database for attack intelligence | `ai_analyzer` |
| **SQLite** | Lightweight relational DB for operational data | `honeypot`, `detection`, `response`, `api` |
| **Motor** | Async MongoDB driver for Python | `ai_analyzer/database.py` |
| **httpx** | Async HTTP client for inter-service calls | `gateway`, `ai_analyzer` |
| **React Native + Expo** | Cross-platform mobile dashboard | `monitorapp` |
| **CVSS** | Industry-standard vulnerability scoring | `ai_analyzer/cvss_engine.py` |
| **MITRE ATT&CK** | Threat classification framework | `detection/mitre_mapper.py` |
| **OWASP** | Web security categorization | `ai_analyzer/threat_intel.py` |
| **Pydantic** | Data validation and schema enforcement | All FastAPI services |

---

## 🐳 Infrastructure: `docker-compose.yml`

The root `docker-compose.yml` is what makes CyberGuard a one-command deployment. It defines:

**Network:** All services communicate over `hackzion_net`, a private Docker bridge network. No service is reachable from outside except through the `proxy` (port 80) and services with explicit port mappings.

**Volumes:**
- `db_data` — Shared SQLite database volume. Mounted by `honeypot`, `detection`, `response`, and `api` at `/data/`.
- `mongo_data` — Persistent MongoDB storage for `ai_analyzer`.
- `ollama_data` — Persistent Llama3 model weights so they don't need to be re-downloaded on container restart.

**Service startup order (via `depends_on`):**
```
mongo, ollama → ai_analyzer → backend, honeypot, detection, response, api → gateway → proxy
```

**Port exposure:**
| Service | Internal Port | External Port | Purpose |
|---|---|---|---|
| `proxy` | 80 | **80** | Public entry point |
| `detection` | 8001 | 8001 | Debug access |
| `response` | 8002 | 8002 | Debug access |
| `api` | 8003 | 8003 | API access |
| `ai_analyzer` | 8004 | 8004 | AI pipeline access |
| `mongo` | 27017 | 27017 | Database access |
| `ollama` | 11434 | 11434 | LLM access |

---

## 🚀 Getting Started

### Prerequisites

- Docker and Docker Compose installed
- At least 8GB RAM (Llama3 model requires significant memory)
- ~10GB disk space (for the Llama3 model weights)

### Running the System

```bash
# Clone the repository
git clone https://github.com/Code-Knight-Debjit/CyberGuard.git
cd CyberGuard

# Start all services
docker compose up --build

# Pull the Llama3 model into Ollama (first run only)
docker exec -it CyberGuard-ollama-1 ollama pull llama3
```

### Testing the System

```bash
# Simulate an attack (from the simulator folder or manually)
curl -X POST http://localhost/login \
  -d "username=admin' OR 1=1--&password=anything"

# Check the AI analysis results
curl http://localhost:8004/attacks | python3 -m json.tool

# Check detection service
curl http://localhost:8001/health

# View gateway risk store
curl http://localhost/risk/store
```

### Running the Monitor App

```bash
cd monitorapp
npm install
npx expo start
```

Open the Expo Go app on your phone and scan the QR code, or press `w` to open in the browser.

---

## 💡 Why Each Component Matters

**Why not just use a firewall to block attackers?**
Firewalls block and log — they don't study. CyberGuard's philosophy is that an attacker you redirect into a honeypot gives you far more intelligence than an attacker you simply block. You learn their tools, techniques, and patterns.

**Why local LLM instead of an API like OpenAI?**
Security research involves sensitive data — attacker IPs, payloads, and potentially personal information captured in attacks. Using a local model (Llama3 via Ollama) ensures that no attack data leaves your infrastructure. It also means the system works completely offline and at zero ongoing API cost.

**Why two databases (SQLite + MongoDB)?**
SQLite is fast and simple — perfect for operational data that needs quick reads and writes from multiple services simultaneously (IP scores, block lists, session records). MongoDB is document-oriented and schema-flexible — perfect for the richly structured, variable-length AI analysis reports that `ai_analyzer` produces.

**Why a mobile app instead of a web dashboard?**
A security operations center doesn't stop when you leave your desk. A mobile-first dashboard means you can monitor live attacks from anywhere. It also makes for a far more compelling demo.

**Why MITRE ATT&CK and CVSS?**
These are the universal languages of cybersecurity. Tagging every attack with a MITRE technique ID means the data can be correlated with CVE databases, threat feeds, and other security tools. CVSS scoring makes severity immediately comparable across attack types.

---

## 🧩 The Philosophy

CyberGuard is built on three core principles:

**Deception over denial** — Don't block attackers, mislead them. Every second they spend in the honeypot is a second of intelligence gathered.

**Analysis over alerting** — Raw logs are noise. The system converts every attack into structured, scored, categorized intelligence before it ever reaches a human.

**Observe, don't disrupt** — Real users are never affected. The risk engine is conservative with legitimate traffic, and all enforcement happens only in the isolated honeypot environment.

---

*Built with Python, FastAPI, React Native, Ollama, MongoDB, Docker, and a lot of security thinking by [Code-Knight-Debjit](https://github.com/Code-Knight-Debjit).*

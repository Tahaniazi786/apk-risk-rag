# GenAI-Based APK Risk Scoring System

A Generative AI-powered forensic analysis system for Android APKs, built around a
**Precedent-Based Verdict Engine** using RAG (Retrieval-Augmented Generation).

> Built for: *Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic
> Analysis, and Risk Scoring of Fraudulent Mobile Applications (APKs) and Malware* (PS1)

---

## What It Does

1. **Static Analysis** (`androguard`) — extracts permissions, API call patterns, hardcoded
   URLs/IPs, and obfuscation indicators from an uploaded APK.
2. **RAG Retrieval** (`ChromaDB` + `sentence-transformers`) — converts the APK's behavior
   profile into an embedding and retrieves:
   - Top-5 most similar **precedent malware cases** (Anubis, Hydra, SOVA, TeaBot, etc.)
   - Relevant **RBI/CERT-In compliance** snippets
   - Relevant **MITRE ATT&CK for Mobile** techniques
3. **LLM Reasoning** (`Groq` — free, fast Llama 3.3 70B) — produces a structured forensic
   verdict including:
   - **Precedent comparison** ("89% similar to Anubis v1...")
   - **Malware family evolution tree** (rendered as a Mermaid diagram)
   - **Attack kill-chain reconstruction** (step-by-step, mapped to ATT&CK techniques)
   - **Explainable score breakdown** (factor-by-factor risk points)
   - **Counterfactual explanation** ("if permission X were absent, score would drop to Y")
   - **Threat actor attribution**
   - **Predicted next actions** (what the malware is likely to do next)
   - **Regulatory compliance violations** (RBI/CERT-In grounding)
4. **Analyst Memory (Self-Improving Loop)** — analysts can confirm or correct a verdict,
   which is added back into the ChromaDB knowledge base for future retrievals.

---

## Tech Stack (All Free)

| Layer | Tool |
|---|---|
| Static analysis | `androguard` |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2) |
| Vector DB | `ChromaDB` (local, persistent) |
| LLM | `Groq` API (Llama 3.3 70B, free tier) |
| Backend | `FastAPI` |
| Frontend | `React` + `Vite` + `Tailwind` + `Recharts` + `Mermaid.js` |

---

## Setup

### Option A: Docker (fastest)

```bash
export GROQ_API_KEY=your_groq_api_key_here
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`

### Option B: Manual

#### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a **free Groq API key** at https://console.groq.com/keys, then:

```bash
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
export GROQ_API_KEY=your_key_here   # or use python-dotenv / direnv
```

Run the server (this also seeds ChromaDB on first startup):

```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Docs at `http://localhost:8000/docs`.

#### 2. Frontend

```bash
cd frontend
npm install
cp .env.example .env   # adjust VITE_API_BASE if backend runs elsewhere
npm run dev
```

Open `http://localhost:5173`.

---

## Usage

1. Open the web app, upload a `.apk` file, click **Analyze APK**.
2. The system runs static analysis → RAG retrieval → LLM reasoning, and displays:
   - Risk score (0-100) with severity badge
   - Verdict summary
   - Precedent case matches with similarity %
   - Malware family evolution tree diagram
   - Attack kill-chain timeline
   - Explainable score breakdown chart + counterfactual
   - Threat actor attribution + predicted next actions
   - Regulatory compliance violations
3. Use **Confirm Verdict** or **Correct Verdict** to feed analyst decisions back into the
   knowledge base — watch the case count increase (self-improving demo).

### Demo Mode (no LLM call)

Click **"Use demo mode (no LLM call)"** to see a pre-baked but realistic verdict — useful for
offline demos or if you hit Groq's free-tier rate limit during judging.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze` | Upload an APK, get full verdict |
| `POST` | `/analyze-text` | Analyze a manual behavior-profile string (no APK needed, good for testing) |
| `POST` | `/feedback` | Submit analyst confirmation/correction → added to knowledge base |
| `GET` | `/db-stats` | Current knowledge base statistics |
| `POST` | `/seed?force=true` | Re-seed the knowledge base from scratch |
| `GET` | `/health` | Health check |

### Quick test without an APK file

```bash
curl -X POST "http://localhost:8000/analyze-text" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_text": "App requests READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW. Contacts C2 via Telegram Bot API.",
    "detected_behaviors": ["sms_otp_access", "sms_interception", "accessibility_abuse", "overlay_attack", "c2_communication", "encrypted_exfiltration"]
  }'
```

Or run the included smoke test (tests both a malicious-like and benign-like profile):

```bash
python3 test_api.py              # uses live Groq LLM
python3 test_api.py --mock       # uses demo/mock fallback, no API key needed
```

---

## Project Structure

```
apk-risk-rag/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + endpoints
│   │   ├── static_analysis.py   # androguard-based APK feature extraction
│   │   ├── vector_store.py       # ChromaDB RAG layer
│   │   ├── llm_reasoning.py       # Groq LLM prompt + structured verdict
│   │   └── mock_data.py           # Demo-mode fallback verdicts
│   ├── seed/
│   │   └── seed_data.py           # Precedent cases, compliance snippets, ATT&CK techniques
│   ├── data/                       # ChromaDB persistent storage (gitignored)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   │       ├── RiskScoreBadge.jsx
│   │       ├── ScoreBreakdownChart.jsx
│   │       ├── PrecedentMatches.jsx
│   │       ├── KillChain.jsx
│   │       ├── MermaidDiagram.jsx
│   │       └── AnalystFeedback.jsx
│   └── package.json
└── sample_apks/                    # place test APKs here (gitignored)
```

---

## Notes for Demo

- The knowledge base seeds itself with **20 precedent cases** (Anubis, Hydra, SOVA, TeaBot,
  EventBot, FluBot, Cerberus, BankBot, spyware, fake banking clones, fake investment apps,
  and benign apps for contrast), **6 RBI/CERT-In compliance snippets**, and **14 MITRE ATT&CK
  for Mobile techniques**.
- If `androguard` analysis on a real malware sample is too slow/risky for a live demo, use a
  benign test APK or the demo mode toggle.
- The "Analyst Memory" feature genuinely writes to ChromaDB — the case count visibly
  increases after clicking Confirm/Correct, demonstrating the self-improving loop live.

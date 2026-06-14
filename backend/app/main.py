"""
Main FastAPI application for the GenAI-Based APK Risk Scoring System.

Endpoints:
- POST /analyze        : upload an APK, run full pipeline (static analysis -> RAG -> LLM verdict)
- POST /feedback        : analyst confirms/corrects a verdict -> added to knowledge base (self-improving)
- GET  /db-stats         : current knowledge base statistics
- POST /seed             : (re)seed the knowledge base
- GET  /health           : health check
"""

import os
import shutil
import tempfile
import traceback

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import vector_store, static_analysis, llm_reasoning, mock_data

app = FastAPI(title="GenAI APK Risk Scoring System", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    # Ensure DB is seeded on startup
    try:
        stats = vector_store.seed_database(force=False)
        print(f"[startup] Knowledge base ready: {stats}")
    except Exception as e:
        print(f"[startup] Warning: seeding failed: {e}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db-stats")
def db_stats():
    return vector_store.get_db_stats()


@app.post("/seed")
def seed(force: bool = False):
    stats = vector_store.seed_database(force=force)
    return {"message": "Knowledge base seeded", "stats": stats}


@app.post("/analyze")
async def analyze_apk(file: UploadFile = File(...), use_mock: bool = False):
    """
    Full pipeline:
    1. Save uploaded APK
    2. Static analysis (androguard) -> behavior profile
    3. RAG retrieval: similar precedent cases, compliance snippets, ATT&CK techniques
    4. LLM reasoning -> structured verdict (or mock fallback)
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload a valid .apk file")

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, file.filename)

    try:
        with open(tmp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # Step 1: Static analysis
        try:
            static_profile = static_analysis.analyze_apk(tmp_path)
        except Exception as e:
            raise HTTPException(
                status_code=422,
                detail=f"Static analysis failed - the file may not be a valid APK: {e}"
            )

        # Step 2: RAG retrieval
        retrieved_cases = vector_store.retrieve_similar_cases(static_profile["profile_text"], n_results=5)
        compliance_matches = vector_store.retrieve_compliance_matches(
            static_profile["detected_behaviors"], n_results=3
        )
        attack_techniques = vector_store.retrieve_attack_techniques(
            static_profile["detected_behaviors"], n_results=5
        )

        # Step 3: LLM reasoning (with mock fallback)
        verdict = None
        used_mock = False
        if use_mock:
            verdict = mock_data.get_mock_verdict(static_profile["detected_behaviors"])
            used_mock = True
        else:
            try:
                verdict = llm_reasoning.get_verdict(
                    static_profile, retrieved_cases, compliance_matches, attack_techniques
                )
            except Exception as e:
                print(f"[analyze] LLM call failed, falling back to mock: {e}")
                traceback.print_exc()
                verdict = mock_data.get_mock_verdict(static_profile["detected_behaviors"])
                used_mock = True

        return {
            "static_profile": static_profile,
            "retrieved_cases": retrieved_cases,
            "compliance_matches": compliance_matches,
            "attack_techniques": attack_techniques,
            "verdict": verdict,
            "used_mock_fallback": used_mock,
        }

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


class FeedbackRequest(BaseModel):
    profile_text: str
    family: str
    variant: str
    risk_score: int
    score_breakdown: dict
    known_followup_actions: list


@app.post("/feedback")
def submit_feedback(feedback: FeedbackRequest):
    """Analyst confirms/corrects a verdict -> added to knowledge base (self-improving loop)."""
    result = vector_store.add_analyst_feedback(
        profile_text=feedback.profile_text,
        family=feedback.family,
        variant=feedback.variant,
        risk_score=feedback.risk_score,
        score_breakdown=feedback.score_breakdown,
        known_followup_actions=feedback.known_followup_actions,
    )
    stats = vector_store.get_db_stats()
    return {
        "message": f"Case {result['id']} added to knowledge base. Total cases: {result['total_cases']}.",
        "stats": stats,
    }


@app.post("/analyze-text")
def analyze_text(profile_text: str, detected_behaviors: list[str] = [], use_mock: bool = False):
    """
    Analyze a manually-provided behavior profile (for testing without an actual APK file).
    Useful for demo/testing without needing real APK samples.
    """
    static_profile = {
        "package_name": "manual.input",
        "app_name": "Manual Test Profile",
        "permissions": [],
        "detected_behaviors": detected_behaviors,
        "network_indicators": {},
        "obfuscation_ratio": 0.0,
        "profile_text": profile_text,
    }

    retrieved_cases = vector_store.retrieve_similar_cases(profile_text, n_results=5)
    compliance_matches = vector_store.retrieve_compliance_matches(detected_behaviors, n_results=3)
    attack_techniques = vector_store.retrieve_attack_techniques(detected_behaviors, n_results=5)

    used_mock = False
    if use_mock:
        verdict = mock_data.get_mock_verdict(detected_behaviors)
        used_mock = True
    else:
        try:
            verdict = llm_reasoning.get_verdict(static_profile, retrieved_cases, compliance_matches, attack_techniques)
        except Exception as e:
            print(f"[analyze-text] LLM call failed, falling back to mock: {e}")
            verdict = mock_data.get_mock_verdict(detected_behaviors)
            used_mock = True

    return {
        "static_profile": static_profile,
        "retrieved_cases": retrieved_cases,
        "compliance_matches": compliance_matches,
        "attack_techniques": attack_techniques,
        "verdict": verdict,
        "used_mock_fallback": used_mock,
    }

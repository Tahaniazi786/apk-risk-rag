"""
ChromaDB-backed vector store for the Precedent-Based Verdict Engine.
Handles seeding, retrieval, and analyst-feedback-driven self-improvement.
"""

import os
import json
import chromadb
from sentence_transformers import SentenceTransformer

from seed.seed_data import SEED_CASES, COMPLIANCE_SNIPPETS, ATTACK_TECHNIQUES

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "chroma_db")

_client = None
_embedder = None


def get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=DB_PATH)
    return _client


def get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder


def get_collections():
    client = get_client()
    cases = client.get_or_create_collection("malware_cases")
    compliance = client.get_or_create_collection("compliance_snippets")
    techniques = client.get_or_create_collection("attack_techniques")
    return cases, compliance, techniques


def seed_database(force: bool = False):
    """Populate ChromaDB with seed cases, compliance snippets, and ATT&CK techniques."""
    cases, compliance, techniques = get_collections()
    embedder = get_embedder()

    if force:
        # wipe and recreate
        client = get_client()
        for name in ["malware_cases", "compliance_snippets", "attack_techniques"]:
            try:
                client.delete_collection(name)
            except Exception:
                pass
        cases, compliance, techniques = get_collections()

    existing_ids = set(cases.get()["ids"]) if cases.count() > 0 else set()

    # Seed malware cases
    new_cases = [c for c in SEED_CASES if c["id"] not in existing_ids]
    if new_cases:
        texts = [c["profile_text"] for c in new_cases]
        embeddings = embedder.encode(texts).tolist()
        cases.add(
            ids=[c["id"] for c in new_cases],
            embeddings=embeddings,
            documents=texts,
            metadatas=[
                {
                    "family": c["family"],
                    "variant": c["variant"],
                    "risk_score": c["risk_score"],
                    "score_breakdown": json.dumps(c["score_breakdown"]),
                    "known_followup_actions": json.dumps(c["known_followup_actions"]),
                    "source": "seed",
                }
                for c in new_cases
            ],
        )

    # Seed compliance snippets
    existing_compliance_ids = set(compliance.get()["ids"]) if compliance.count() > 0 else set()
    new_compliance = [c for c in COMPLIANCE_SNIPPETS if c["id"] not in existing_compliance_ids]
    if new_compliance:
        texts = [c["text"] for c in new_compliance]
        embeddings = embedder.encode(texts).tolist()
        compliance.add(
            ids=[c["id"] for c in new_compliance],
            embeddings=embeddings,
            documents=texts,
            metadatas=[
                {
                    "title": c["title"],
                    "applicable_behaviors": json.dumps(c["applicable_behaviors"]),
                }
                for c in new_compliance
            ],
        )

    # Seed ATT&CK techniques
    existing_tech_ids = set(techniques.get()["ids"]) if techniques.count() > 0 else set()
    new_tech = [t for t in ATTACK_TECHNIQUES if t["id"] not in existing_tech_ids]
    if new_tech:
        texts = [t["description"] for t in new_tech]
        embeddings = embedder.encode(texts).tolist()
        techniques.add(
            ids=[t["id"] for t in new_tech],
            embeddings=embeddings,
            documents=texts,
            metadatas=[
                {
                    "name": t["name"],
                    "applicable_behaviors": json.dumps(t["applicable_behaviors"]),
                }
                for t in new_tech
            ],
        )

    return {
        "malware_cases": cases.count(),
        "compliance_snippets": compliance.count(),
        "attack_techniques": techniques.count(),
    }


def retrieve_similar_cases(profile_text: str, n_results: int = 5):
    """Retrieve top-N similar precedent cases for a given behavior profile."""
    cases, _, _ = get_collections()
    embedder = get_embedder()
    query_embedding = embedder.encode([profile_text]).tolist()

    n_results = min(n_results, cases.count()) if cases.count() > 0 else 0
    if n_results == 0:
        return []

    results = cases.query(query_embeddings=query_embedding, n_results=n_results)

    retrieved = []
    for doc, meta, dist in zip(
        results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        similarity_pct = round(max(0.0, 1 - dist) * 100, 1)
        retrieved.append(
            {
                "family": meta.get("family"),
                "variant": meta.get("variant"),
                "risk_score": meta.get("risk_score"),
                "profile_text": doc,
                "score_breakdown": json.loads(meta.get("score_breakdown", "{}")),
                "known_followup_actions": json.loads(meta.get("known_followup_actions", "[]")),
                "similarity_percent": similarity_pct,
                "source": meta.get("source", "seed"),
            }
        )
    return retrieved


def retrieve_compliance_matches(detected_behaviors: list, n_results: int = 3):
    """Retrieve compliance snippets relevant to the detected behaviors."""
    _, compliance, _ = get_collections()
    if compliance.count() == 0:
        return []

    embedder = get_embedder()
    query_text = "Behaviors detected: " + ", ".join(detected_behaviors)
    query_embedding = embedder.encode([query_text]).tolist()

    n_results = min(n_results, compliance.count())
    results = compliance.query(query_embeddings=query_embedding, n_results=n_results)

    matches = []
    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        matches.append(
            {
                "title": meta.get("title"),
                "text": doc,
                "applicable_behaviors": json.loads(meta.get("applicable_behaviors", "[]")),
            }
        )
    return matches


def retrieve_attack_techniques(detected_behaviors: list, n_results: int = 5):
    """Retrieve MITRE ATT&CK Mobile techniques relevant to the detected behaviors."""
    _, _, techniques = get_collections()
    if techniques.count() == 0:
        return []

    embedder = get_embedder()
    query_text = "Behaviors detected: " + ", ".join(detected_behaviors)
    query_embedding = embedder.encode([query_text]).tolist()

    n_results = min(n_results, techniques.count())
    results = techniques.query(query_embeddings=query_embedding, n_results=n_results)

    matches = []
    for doc, meta, _id in zip(results["documents"][0], results["metadatas"][0], results["ids"][0]):
        matches.append(
            {
                "technique_id": _id,
                "name": meta.get("name"),
                "description": doc,
                "applicable_behaviors": json.loads(meta.get("applicable_behaviors", "[]")),
            }
        )
    return matches


def add_analyst_feedback(profile_text: str, family: str, variant: str, risk_score: int,
                          score_breakdown: dict, known_followup_actions: list):
    """Add an analyst-confirmed/corrected case back into the knowledge base (self-improving loop)."""
    cases, _, _ = get_collections()
    embedder = get_embedder()

    existing_count = cases.count()
    new_id = f"analyst_case_{existing_count + 1}"

    embedding = embedder.encode([profile_text]).tolist()
    cases.add(
        ids=[new_id],
        embeddings=embedding,
        documents=[profile_text],
        metadatas=[
            {
                "family": family,
                "variant": variant,
                "risk_score": risk_score,
                "score_breakdown": json.dumps(score_breakdown),
                "known_followup_actions": json.dumps(known_followup_actions),
                "source": "analyst_confirmed",
            }
        ],
    )
    return {"id": new_id, "total_cases": cases.count()}


def get_db_stats():
    cases, compliance, techniques = get_collections()
    return {
        "malware_cases": cases.count(),
        "compliance_snippets": compliance.count(),
        "attack_techniques": techniques.count(),
    }

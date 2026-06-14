"""
LLM reasoning layer using Groq API (free tier, fast inference, JSON mode support).
Takes the static analysis profile + RAG-retrieved precedent cases, compliance
snippets, and ATT&CK techniques, and produces the full structured verdict.
"""

import os
import json
import re
from groq import Groq

GROQ_MODEL = "llama-3.3-70b-versatile"

_client = None


def get_groq_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY environment variable not set. "
                "Get a free key at https://console.groq.com/keys"
            )
        _client = Groq(api_key=api_key)
    return _client


def clean_json_response(text: str) -> str:
    """Strip markdown code fences and surrounding text from LLM JSON output."""
    text = text.strip()
    # Remove ```json ... ``` or ``` ... ``` fences
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)
    # If there's leading/trailing junk, try to extract the outermost {...}
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1:
        text = text[first_brace : last_brace + 1]
    return text.strip()


def build_prompt(static_profile: dict, retrieved_cases: list, compliance_matches: list,
                  attack_techniques: list) -> str:
    profile_text = static_profile["profile_text"]
    detected_behaviors = static_profile["detected_behaviors"]

    cases_block = "\n".join(
        f"- [{c['similarity_percent']}% similar] Family: {c['family']} ({c['variant']}), "
        f"Risk Score: {c['risk_score']}\n"
        f"  Profile: {c['profile_text']}\n"
        f"  Score Breakdown: {json.dumps(c['score_breakdown'])}\n"
        f"  Known Follow-up Actions: {json.dumps(c['known_followup_actions'])}"
        for c in retrieved_cases
    ) or "No precedent cases found in knowledge base."

    compliance_block = "\n".join(
        f"- {c['title']}: {c['text']}" for c in compliance_matches
    ) or "No specific compliance matches found."

    attack_block = "\n".join(
        f"- {t['technique_id']} ({t['name']}): {t['description']}" for t in attack_techniques
    ) or "No specific ATT&CK techniques matched."

    prompt = f"""You are a senior malware forensic analyst at a bank's cybersecurity unit. You analyze
suspicious Android APKs by comparing them against a precedent database of known malware cases,
applicable banking regulations, and MITRE ATT&CK for Mobile techniques.

=== NEW APK BEHAVIOR PROFILE ===
{profile_text}

Detected behavior tags: {', '.join(detected_behaviors) if detected_behaviors else 'none'}

=== RETRIEVED PRECEDENT CASES (most similar from knowledge base) ===
{cases_block}

=== RETRIEVED COMPLIANCE/REGULATORY CONTEXT ===
{compliance_block}

=== RETRIEVED MITRE ATT&CK FOR MOBILE TECHNIQUES ===
{attack_block}

=== YOUR TASK ===
Produce a complete forensic analysis as a single JSON object with EXACTLY this structure:

{{
  "similarity_matches": [
    {{"family": "...", "variant": "...", "similarity_percent": <number from retrieved data>, "reasoning": "1-2 sentences on what matches and what differs"}}
  ],
  "evolution_tree": {{
    "closest_family": "...",
    "relation_description": "1-2 sentences describing how this APK relates to the closest matched family/variant (e.g. 'appears to be a variant of X with additional Y capability')",
    "mermaid_diagram": "valid Mermaid.js graph syntax (graph TD) showing closest_family -> known variants -> this new APK with similarity percentage on the edge to the new APK"
  }},
  "kill_chain": [
    {{"step": 1, "technique_id": "...", "technique_name": "...", "description": "plain-English description of what the app does at this step, grounded in the detected behaviors"}}
  ],
  "score_breakdown": {{"factor_name": <integer points>, ...}},
  "total_risk_score": <integer 0-100, should roughly equal sum of score_breakdown but use judgment>,
  "counterfactual": "If [specific permission/behavior from the profile] were absent, the risk score would likely drop to approximately [X] because [reason]. Be specific to THIS profile.",
  "threat_actor_attribution": "1-2 sentences on what type of threat actor / campaign this resembles, grounded in retrieved precedent cases",
  "predicted_next_actions": [
    {{"action": "...", "probability_percent": <number>}}
  ],
  "compliance_violations": [
    {{"regulation": "...", "violation_description": "1-2 sentences on what behavior violates this and why"}}
  ],
  "verdict_summary": "2-3 sentence plain-English summary for a bank investigator with no technical background, including the overall verdict (e.g. confirmed malicious / likely malicious / suspicious / likely benign) and recommended action"
}}

IMPORTANT RULES:
- Ground every claim in either the new APK's detected behaviors or the retrieved precedent/compliance/ATT&CK data. Do not invent details not supported by the profile.
- If detected_behaviors is empty or very minimal and no precedent cases are highly similar (all under ~40% similarity), the total_risk_score should be LOW (under 20) and the verdict should reflect a likely benign app, with similarity_matches noting "no significant precedent match" rather than forcing a malicious comparison.
- score_breakdown values must sum to approximately total_risk_score (within 5 points).
- mermaid_diagram must be syntactically valid Mermaid graph TD syntax, using simple node IDs (no special characters), e.g.:
  graph TD
    A[Anubis] --> B[Anubis v2]
    A --> C[This APK - 89% similar]
- Output ONLY the JSON object. No markdown fences, no preamble, no explanation outside the JSON.
"""
    return prompt


def get_verdict(static_profile: dict, retrieved_cases: list, compliance_matches: list,
                 attack_techniques: list) -> dict:
    """Call the LLM to produce the full structured verdict."""
    client = get_groq_client()
    prompt = build_prompt(static_profile, retrieved_cases, compliance_matches, attack_techniques)

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": "You are a precise forensic analysis system that outputs only valid JSON."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=3000,
        response_format={"type": "json_object"},
    )

    raw_text = response.choices[0].message.content
    cleaned = clean_json_response(raw_text)

    try:
        verdict = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\nRaw output: {raw_text[:1000]}")

    return verdict

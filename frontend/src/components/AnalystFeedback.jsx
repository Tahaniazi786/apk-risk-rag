import { useState } from "react";
import { CheckCircle2, Edit3, Loader2 } from "lucide-react";
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export default function AnalystFeedback({ result, onFeedbackSubmitted }) {
  const [mode, setMode] = useState("idle"); // idle | editing | submitting | done
  const [family, setFamily] = useState(
    result?.verdict?.evolution_tree?.closest_family || result?.verdict?.similarity_matches?.[0]?.family || ""
  );
  const [variant, setVariant] = useState(result?.verdict?.similarity_matches?.[0]?.variant || "");
  const [riskScore, setRiskScore] = useState(result?.verdict?.total_risk_score ?? 0);
  const [message, setMessage] = useState("");

  const submit = async () => {
    setMode("submitting");
    try {
      const res = await axios.post(`${API_BASE}/feedback`, {
        profile_text: result.static_profile.profile_text,
        family,
        variant,
        risk_score: Number(riskScore),
        score_breakdown: result.verdict.score_breakdown || {},
        known_followup_actions: result.verdict.predicted_next_actions || [],
      });
      setMessage(res.data.message);
      setMode("done");
      onFeedbackSubmitted && onFeedbackSubmitted(res.data.stats);
    } catch (e) {
      setMessage("Failed to submit feedback: " + (e?.response?.data?.detail || e.message));
      setMode("idle");
    }
  };

  if (mode === "done") {
    return (
      <div className="flex items-center gap-2 text-emerald-400 text-sm glass rounded-xl p-4 border border-emerald-900/40">
        <CheckCircle2 size={18} />
        <span>{message}</span>
      </div>
    );
  }

  if (mode === "idle") {
    return (
      <div className="flex flex-wrap gap-3">
        <button
          onClick={submit}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition"
        >
          <CheckCircle2 size={16} /> Confirm Verdict
        </button>
        <button
          onClick={() => setMode("editing")}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium transition"
        >
          <Edit3 size={16} /> Correct Verdict
        </button>
      </div>
    );
  }

  if (mode === "editing") {
    return (
      <div className="glass rounded-xl p-4 border border-slate-700/50 space-y-3">
        <div className="grid sm:grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Family</label>
            <input
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1 text-sm text-slate-100"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Variant</label>
            <input
              value={variant}
              onChange={(e) => setVariant(e.target.value)}
              className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1 text-sm text-slate-100"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Risk Score</label>
            <input
              type="number"
              min="0"
              max="100"
              value={riskScore}
              onChange={(e) => setRiskScore(e.target.value)}
              className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1 text-sm text-slate-100"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={submit}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition"
          >
            Submit Correction
          </button>
          <button
            onClick={() => setMode("idle")}
            className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium transition"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (mode === "submitting") {
    return (
      <div className="flex items-center gap-2 text-slate-400 text-sm">
        <Loader2 size={16} className="animate-spin" /> Submitting feedback...
      </div>
    );
  }

  return null;
}

import { useState, useRef } from "react";
import axios from "axios";
import {
  Upload,
  ShieldAlert,
  Loader2,
  Database,
  FileWarning,
  Network,
  ListTree,
  Scale,
  TrendingUp,
  Sparkles,
} from "lucide-react";

import RiskScoreBadge from "./components/RiskScoreBadge";
import ScoreBreakdownChart from "./components/ScoreBreakdownChart";
import PrecedentMatches from "./components/PrecedentMatches";
import KillChain from "./components/KillChain";
import MermaidDiagram from "./components/MermaidDiagram";
import AnalystFeedback from "./components/AnalystFeedback";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

function Section({ icon: Icon, title, children }) {
  return (
    <div className="glass rounded-2xl p-5 border border-slate-700/40">
      <div className="flex items-center gap-2 mb-4">
        <Icon size={18} className="text-sky-400" />
        <h3 className="font-semibold text-slate-100">{title}</h3>
      </div>
      {children}
    </div>
  );
}

export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [dbStats, setDbStats] = useState(null);
  const fileInputRef = useRef(null);

  const handleAnalyze = async (useMock = false) => {
    if (!file) {
      setError("Please select an APK file first.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await axios.post(`${API_BASE}/analyze?use_mock=${useMock}`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 120000,
      });
      setResult(res.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const handleFeedbackSubmitted = (stats) => {
    setDbStats(stats);
  };

  const verdict = result?.verdict;

  return (
    <div className="min-h-screen bg-[#0a0e17] bg-[radial-gradient(circle_at_top_right,_rgba(56,189,248,0.08),_transparent_50%),radial-gradient(circle_at_bottom_left,_rgba(168,85,247,0.06),_transparent_50%)]">
      <div className="max-w-6xl mx-auto px-4 py-10">
        {/* Header */}
        <header className="mb-10 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/50 border border-sky-900/50 text-sky-300 text-xs font-medium mb-4">
            <Sparkles size={14} /> GenAI-Powered Precedent Verdict Engine
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold text-slate-50 mb-2">
            APK Malware Risk Scoring System
          </h1>
          <p className="text-slate-400 max-w-2xl mx-auto text-sm">
            Upload a suspicious APK. Our system runs static analysis, retrieves similar precedent
            cases via RAG, and produces a forensic verdict with kill-chain reconstruction,
            regulatory grounding, and threat attribution.
          </p>
        </header>

        {/* Upload Card */}
        <div className="glass rounded-2xl p-6 border border-slate-700/40 mb-8">
          <div className="flex flex-col sm:flex-row items-center gap-4">
            <div
              onClick={() => fileInputRef.current?.click()}
              className="flex-1 w-full border-2 border-dashed border-slate-600 hover:border-sky-500 rounded-xl p-6 text-center cursor-pointer transition"
            >
              <Upload className="mx-auto mb-2 text-slate-400" size={28} />
              <p className="text-sm text-slate-300">
                {file ? file.name : "Click to select an .apk file"}
              </p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk"
                className="hidden"
                onChange={(e) => setFile(e.target.files[0])}
              />
            </div>
            <div className="flex flex-col gap-2 w-full sm:w-auto">
              <button
                onClick={() => handleAnalyze(false)}
                disabled={loading}
                className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-medium transition whitespace-nowrap"
              >
                {loading ? <Loader2 size={18} className="animate-spin" /> : <ShieldAlert size={18} />}
                Analyze APK
              </button>
              <button
                onClick={() => handleAnalyze(true)}
                disabled={loading}
                className="text-xs text-slate-400 hover:text-slate-200 underline"
              >
                Use demo mode (no LLM call)
              </button>
            </div>
          </div>
          {error && (
            <div className="mt-4 flex items-center gap-2 text-red-400 text-sm bg-red-950/30 border border-red-900/40 rounded-lg p-3">
              <FileWarning size={16} /> {error}
            </div>
          )}
          {result?.used_mock_fallback && (
            <div className="mt-4 flex items-center gap-2 text-amber-400 text-sm bg-amber-950/30 border border-amber-900/40 rounded-lg p-3">
              <Sparkles size={16} /> Showing fallback/demo verdict (live LLM call was skipped or unavailable).
            </div>
          )}
        </div>

        {/* Results */}
        {result && verdict && (
          <div className="space-y-6">
            {/* Top row: Risk score + verdict summary */}
            <div className="grid sm:grid-cols-[200px_1fr] gap-6 items-stretch">
              <RiskScoreBadge score={verdict.total_risk_score} />
              <div className="glass rounded-2xl p-5 border border-slate-700/40 flex flex-col justify-center">
                <h3 className="font-semibold text-slate-100 mb-2">Verdict Summary</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{verdict.verdict_summary}</p>
                <div className="mt-3 text-xs text-slate-400">
                  App: <span className="text-slate-300">{result.static_profile.app_name}</span> (
                  {result.static_profile.package_name})
                </div>
              </div>
            </div>

            {/* Precedent matches */}
            <Section icon={Database} title="1. Precedent-Based Verdict — Similar Cases">
              <PrecedentMatches matches={verdict.similarity_matches} />
            </Section>

            {/* Evolution tree */}
            <Section icon={ListTree} title="Malware Family Evolution Tree">
              {verdict.evolution_tree?.relation_description && (
                <p className="text-sm text-slate-300 mb-3">{verdict.evolution_tree.relation_description}</p>
              )}
              {verdict.evolution_tree?.mermaid_diagram && (
                <MermaidDiagram chart={verdict.evolution_tree.mermaid_diagram} />
              )}
            </Section>

            {/* Kill chain */}
            <Section icon={Network} title="2. Attack Narrative Reconstruction (Kill Chain)">
              <KillChain steps={verdict.kill_chain} />
            </Section>

            {/* Score breakdown */}
            <Section icon={TrendingUp} title="Explainability — Score Breakdown">
              <ScoreBreakdownChart breakdown={verdict.score_breakdown} />
              {verdict.counterfactual && (
                <div className="mt-4 text-sm text-slate-300 bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                  <span className="font-semibold text-sky-400">Counterfactual: </span>
                  {verdict.counterfactual}
                </div>
              )}
            </Section>

            {/* Threat attribution + predicted next actions */}
            <div className="grid sm:grid-cols-2 gap-6">
              <Section icon={ShieldAlert} title="Threat Actor Attribution">
                <p className="text-sm text-slate-300 leading-relaxed">{verdict.threat_actor_attribution}</p>
              </Section>
              <Section icon={TrendingUp} title="Predicted Next Actions">
                <div className="space-y-2">
                  {verdict.predicted_next_actions?.map((a, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <span className="text-slate-300">{a.action}</span>
                      <span className="font-mono text-sky-400">{a.probability_percent}%</span>
                    </div>
                  ))}
                  {(!verdict.predicted_next_actions || verdict.predicted_next_actions.length === 0) && (
                    <p className="text-sm text-slate-400">No follow-up actions predicted.</p>
                  )}
                </div>
              </Section>
            </div>

            {/* Compliance */}
            <Section icon={Scale} title="3. Regulatory Compliance Grounding">
              {verdict.compliance_violations && verdict.compliance_violations.length > 0 ? (
                <div className="space-y-3">
                  {verdict.compliance_violations.map((c, i) => (
                    <div key={i} className="border-l-2 border-amber-500/50 pl-3">
                      <div className="text-sm font-semibold text-amber-300">{c.regulation}</div>
                      <p className="text-sm text-slate-300 mt-1">{c.violation_description}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400">No specific regulatory violations identified.</p>
              )}
            </Section>

            {/* Analyst feedback / self-improving loop */}
            <Section icon={Database} title="Analyst Memory — Confirm or Correct This Verdict">
              <AnalystFeedback result={result} onFeedbackSubmitted={handleFeedbackSubmitted} />
              {dbStats && (
                <p className="text-xs text-slate-500 mt-3">
                  Knowledge base now contains {dbStats.malware_cases} cases.
                </p>
              )}
            </Section>
          </div>
        )}

        <footer className="mt-12 text-center text-xs text-slate-500">
          Built for hackathon demo purposes — GenAI-based APK risk scoring with RAG precedent engine.
        </footer>
      </div>
    </div>
  );
}

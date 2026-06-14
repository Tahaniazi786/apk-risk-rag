export default function RiskScoreBadge({ score }) {
  let color = "text-emerald-400 border-emerald-500/40 bg-emerald-950/40";
  let label = "LOW RISK";

  if (score >= 80) {
    color = "text-red-400 border-red-500/40 bg-red-950/40";
    label = "CRITICAL RISK";
  } else if (score >= 60) {
    color = "text-orange-400 border-orange-500/40 bg-orange-950/40";
    label = "HIGH RISK";
  } else if (score >= 35) {
    color = "text-amber-400 border-amber-500/40 bg-amber-950/40";
    label = "MEDIUM RISK";
  } else if (score >= 15) {
    color = "text-yellow-300 border-yellow-500/30 bg-yellow-950/30";
    label = "LOW-MEDIUM RISK";
  }

  return (
    <div className={`flex flex-col items-center justify-center rounded-2xl border-2 p-6 ${color}`}>
      <div className="text-5xl font-bold tabular-nums">{score}</div>
      <div className="text-xs font-semibold tracking-widest mt-1">{label}</div>
      <div className="text-[10px] text-slate-400 mt-1">out of 100</div>
    </div>
  );
}

export default function KillChain({ steps }) {
  if (!steps || steps.length === 0) {
    return (
      <p className="text-sm text-slate-400">
        No attack chain reconstructed — no significant malicious behaviors were detected in sequence.
      </p>
    );
  }

  return (
    <div className="relative pl-6">
      <div className="absolute left-2 top-2 bottom-2 w-0.5 bg-slate-700" />
      <div className="space-y-5">
        {steps.map((step, i) => (
          <div key={i} className="relative">
            <div className="absolute -left-6 top-1 w-4 h-4 rounded-full bg-red-500 border-2 border-slate-900 flex items-center justify-center text-[10px] font-bold text-white">
              {step.step}
            </div>
            <div className="glass rounded-xl p-4 border border-slate-700/50">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950/50 text-red-300 border border-red-900/50">
                  {step.technique_id}
                </span>
                <span className="text-sm font-semibold text-slate-200">{step.technique_name}</span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">{step.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

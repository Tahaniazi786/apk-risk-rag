export default function PrecedentMatches({ matches }) {
  if (!matches || matches.length === 0) {
    return <p className="text-sm text-slate-400">No precedent matches found.</p>;
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {matches.map((m, i) => (
        <div key={i} className="glass rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center justify-between mb-2">
            <div>
              <div className="font-semibold text-slate-100">{m.family}</div>
              <div className="text-xs text-slate-400">{m.variant}</div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-sky-400">{m.similarity_percent}%</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wide">similar</div>
            </div>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{m.reasoning}</p>
        </div>
      ))}
    </div>
  );
}

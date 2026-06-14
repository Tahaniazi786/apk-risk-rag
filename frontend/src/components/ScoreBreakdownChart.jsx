import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";

const COLORS = ["#f87171", "#fb923c", "#fbbf24", "#a3e635", "#38bdf8", "#a78bfa", "#f472b6", "#34d399"];

export default function ScoreBreakdownChart({ breakdown }) {
  if (!breakdown || Object.keys(breakdown).length === 0) {
    return <p className="text-sm text-slate-400">No score breakdown available.</p>;
  }

  const data = Object.entries(breakdown).map(([key, value]) => ({
    name: key.replace(/_/g, " "),
    points: value,
  }));

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 40)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
        <XAxis type="number" stroke="#94a3b8" fontSize={12} />
        <YAxis
          type="category"
          dataKey="name"
          width={150}
          stroke="#94a3b8"
          fontSize={11}
          tick={{ fill: "#cbd5e1" }}
        />
        <Tooltip
          contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
          labelStyle={{ color: "#e2e8f0" }}
        />
        <Bar dataKey="points" radius={[0, 4, 4, 0]}>
          {data.map((_, i) => (
            <Cell key={i} fill={COLORS[i % COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

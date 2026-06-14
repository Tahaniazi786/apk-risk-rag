import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

mermaid.initialize({
  startOnLoad: false,
  theme: "dark",
  themeVariables: {
    background: "#0a0e17",
    primaryColor: "#1e293b",
    primaryTextColor: "#e2e8f0",
    primaryBorderColor: "#475569",
    lineColor: "#64748b",
    secondaryColor: "#334155",
    tertiaryColor: "#1e293b",
  },
});

export default function MermaidDiagram({ chart }) {
  const ref = useRef(null);
  const [error, setError] = useState(null);
  const [svg, setSvg] = useState("");

  useEffect(() => {
    if (!chart) return;
    const id = `mermaid-${Math.random().toString(36).slice(2)}`;
    mermaid
      .render(id, chart)
      .then(({ svg }) => {
        setSvg(svg);
        setError(null);
      })
      .catch((err) => {
        console.error("Mermaid render error:", err);
        setError(err.message);
      });
  }, [chart]);

  if (error) {
    return (
      <div className="text-sm text-amber-400 bg-amber-950/30 p-3 rounded-lg border border-amber-900/50">
        Diagram could not be rendered. Raw diagram code:
        <pre className="mt-2 text-xs overflow-x-auto whitespace-pre-wrap">{chart}</pre>
      </div>
    );
  }

  return (
    <div
      ref={ref}
      className="mermaid-container overflow-x-auto"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

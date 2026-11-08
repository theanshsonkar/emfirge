import { EDGES, LAYOUTS, NODES, type CloudNode, type Damage, type Layout, type NodeId } from "@/content";
import { TestMark } from "./TestMark";

type NodeState = "normal" | "removed" | "broken" | "flagged" | "fixed";

function stateOf(id: NodeId, d: Damage | null): NodeState {
  if (!d) return "normal";
  if (d.removed?.includes(id)) return "removed";
  if (d.broken?.includes(id)) return "broken";
  if (d.flagged?.includes(id)) return "flagged";
  if (d.fixed?.includes(id)) return "fixed";
  return "normal";
}

const CLOUD = "M28 54 C12 54 10 32 28 30 C28 12 56 8 64 20 C74 8 102 14 100 32 C118 34 116 54 100 54 Z";

function Node({
  node,
  layout,
  damage,
  underTest,
}: {
  node: CloudNode;
  layout: Layout;
  damage: Damage | null;
  underTest: boolean;
}) {
  const p = layout.pos[node.id];
  if (!p) return null;
  const { nodeW: w, nodeH: h } = layout;
  const st = stateOf(node.id, damage);
  const changed = damage?.metrics?.[node.id];
  const metric = changed ?? node.metric;
  const dim = node.dim && st === "normal";
  const stroke = st === "removed" ? "#8A8A8A" : st === "broken" ? "#E5341D" : st === "fixed" ? "#1F9D55" : "#000";
  const fill = st === "removed" ? "none" : st === "broken" ? "url(#hatch-red)" : st === "flagged" ? "url(#hatch-yellow)" : "#fff";
  const halo = st === "broken" || st === "flagged" ? { stroke: "#fff", strokeWidth: 3.5, paintOrder: "stroke" as const } : {};
  const isNet = node.id === "internet";
  const nameY = isNet ? h * 0.62 : h * 0.34;
  return (
    <g transform={`translate(${p.x} ${p.y})`} opacity={dim ? 0.5 : 1}>
      {isNet ? (
        <g transform={`translate(${(w - 124) / 2} 0)`}>
          <path d={CLOUD} fill="#fff" stroke="#000" strokeWidth="2" strokeLinejoin="round" />
        </g>
      ) : (
        <rect
          width={w}
          height={h}
          rx="6"
          fill={fill}
          stroke={stroke}
          strokeWidth="2"
          strokeDasharray={st === "removed" || st === "broken" ? "6 4" : undefined}
        />
      )}
      <g textAnchor="middle" fontFamily="var(--font-plex), monospace" {...halo}>
        <text
          x={w / 2}
          y={nameY}
          fontSize="11"
          fontWeight="600"
          fill={st === "removed" ? "#8A8A8A" : "#000"}
          textDecoration={st === "removed" ? "line-through" : undefined}
          {...halo}
        >
          {node.id}
        </text>
        {node.kind ? (
          <text x={w / 2} y={h * 0.55} fontSize="9.5" fill="#4A4A4A" {...halo}>
            {node.kind}
          </text>
        ) : null}
        {metric ? (
          <text
            x={w / 2}
            y={h * 0.8}
            fontSize="10"
            fontWeight={changed ? 600 : 400}
            fill={changed && st !== "removed" ? (st === "flagged" ? "#000" : st === "fixed" ? "#157A41" : "#B8200E") : "#4A4A4A"}
            {...halo}
          >
            {metric}
          </text>
        ) : null}
      </g>
      {underTest ? (
        <g transform={`translate(${w - 15} -13)`}>
          <circle cx="13" cy="13" r="14" fill="#fff" />
          <TestMark size={26} />
        </g>
      ) : null}
    </g>
  );
}

export function DiagramSvg({
  variant,
  damage,
  target,
}: {
  variant: "wide" | "narrow";
  damage: Damage | null;
  target: NodeId | null;
}) {
  const layout = LAYOUTS[variant];
  const exp = damage?.exposure;
  const route = exp ? layout.routes[exp.to] : undefined;
  const hasRemoved = !!damage?.removed?.length;
  return (
    <svg
      viewBox={`0 0 ${layout.w} ${layout.h}`}
      className="block h-auto w-full"
      aria-hidden="true"
      focusable="false"
    >
      {EDGES.map(([a, b]) => {
        const d = layout.edges[`${a}>${b}`];
        if (!d) return null;
        const sa = stateOf(a, damage);
        const sb = stateOf(b, damage);
        const ghost = sa === "removed" || sb === "removed";
        const red = !ghost && hasRemoved && (sa === "broken" || sb === "broken");
        return (
          <path
            key={`${a}>${b}`}
            d={d}
            fill="none"
            strokeWidth="2"
            stroke={ghost ? "#8A8A8A" : red ? "#E5341D" : "#000"}
            strokeDasharray={ghost || red ? "5 4" : undefined}
            markerEnd={`url(#${ghost ? "arrow-ghost" : red ? "arrow-red" : "arrow-ink"})`}
          />
        );
      })}
      {NODES.map((n) => (
        <Node key={n.id} node={n} layout={layout} damage={damage} underTest={target === n.id} />
      ))}
      {exp && route ? (
        <g>
          <path d={route.d} fill="none" stroke="#E5341D" strokeWidth="3.2" strokeLinejoin="round" markerEnd="url(#arrow-red)" className="draw-in" />
          <g transform={`translate(${route.label.x} ${route.label.y})`}>
            <rect
              x={-(exp.label.length * 3.3 + 8)}
              y="-9"
              width={exp.label.length * 6.6 + 16}
              height="18"
              rx="3"
              fill="#fff"
              stroke="#E5341D"
              strokeWidth="1.6"
            />
            <text textAnchor="middle" y="3.6" fontSize="10.5" fontWeight="600" fill="#B8200E" fontFamily="var(--font-plex), monospace">
              {exp.label}
            </text>
          </g>
        </g>
      ) : null}
    </svg>
  );
}

/** Text alternative: every node's state in the selected view. */
export function diagramText(damage: Damage | null): string {
  return NODES.map((n) => {
    const st = stateOf(n.id, damage);
    const m = damage?.metrics?.[n.id] ?? n.metric;
    const s = st === "normal" ? "ok" : st;
    return `${n.id}: ${s}${m ? `, ${m}` : ""}`;
  }).join("; ");
}

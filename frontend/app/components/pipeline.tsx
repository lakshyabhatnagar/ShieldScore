"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { graphEdges, graphNodes, NodeStatus } from "../lib/audit";

type PipelineProps = {
  nodes: Record<string, NodeStatus>;
  elapsed: number;
  phase: "idle" | "checking" | "starting" | "running" | "done" | "error";
};

type Edge = { from: string; to: string; active: boolean; animated: boolean };

function phaseLabel(phase: PipelineProps["phase"], elapsed: number) {
  const time = elapsed >= 60 ? `${Math.floor(elapsed / 60)}m ${elapsed % 60}s` : `${elapsed}s`;
  if (phase === "checking") return "CHECKING ACCESS";
  if (phase === "starting") return "INITIALIZING";
  if (phase === "running") return `RUNNING · ${time}`;
  if (phase === "done") return `COMPLETED · ${time}`;
  if (phase === "error") return "FAILED";
  return "AWAITING INPUT";
}

function statusLabel(status: NodeStatus) {
  return status === "completed" ? "DONE" : status === "error" ? "FAILED" : status === "skipped" ? "SKIPPED" : status.toUpperCase();
}

function PipelineEdge({ edge, canvas }: { edge: Edge; canvas: React.RefObject<HTMLDivElement | null> }) {
  const [path, setPath] = useState("");

  useEffect(() => {
    const draw = () => {
      const root = canvas.current;
      const from = root?.querySelector<HTMLElement>(`[data-node="${edge.from}"]`);
      const to = root?.querySelector<HTMLElement>(`[data-node="${edge.to}"]`);
      if (!root || !from || !to) return;
      const rootBox = root.getBoundingClientRect();
      const fromBox = from.getBoundingClientRect();
      const toBox = to.getBoundingClientRect();
      const startX = fromBox.right - rootBox.left;
      const startY = fromBox.top + fromBox.height / 2 - rootBox.top;
      const endX = toBox.left - rootBox.left;
      const endY = toBox.top + toBox.height / 2 - rootBox.top;
      const middle = (startX + endX) / 2;
      setPath(`M ${startX} ${startY} L ${middle} ${startY} L ${middle} ${endY} L ${endX} ${endY}`);
    };
    draw();
    const observer = new ResizeObserver(draw);
    if (canvas.current) observer.observe(canvas.current);
    const afterLayout = window.setTimeout(draw, 80);
    return () => { observer.disconnect(); window.clearTimeout(afterLayout); };
  }, [canvas, edge.from, edge.to]);

  return <path d={path} className={`graph-edge${edge.active ? " graph-edge--active" : ""}${edge.animated ? " graph-edge--animated" : ""}`} />;
}

export function Pipeline({ nodes, elapsed, phase }: PipelineProps) {
  const canvas = useRef<HTMLDivElement>(null);
  const edges = useMemo(() => graphEdges.map(([from, to]) => ({
    from,
    to,
    active: ["completed", "running"].includes(nodes[from]),
    animated: nodes[from] === "running" || (nodes[from] === "completed" && nodes[to] === "pending"),
  })), [nodes]);

  return (
    <section className="pipeline" aria-label="Pipeline execution" aria-live="polite">
      <header className="pipeline__header">
        <h2>Pipeline Execution</h2>
        <span>{phaseLabel(phase, elapsed)}</span>
      </header>
      <div className="pipeline__scroll">
        <div className="pipeline__grid" ref={canvas}>
          <span className="pipeline__phase pipeline__phase--setup">Setup</span>
          <span className="pipeline__phase pipeline__phase--scan">Scan</span>
          <span className="pipeline__phase pipeline__phase--merge">Merge</span>
          <span className="pipeline__phase pipeline__phase--map">Map</span>
          <span className="pipeline__phase pipeline__phase--report">Report</span>
          <svg className="pipeline__edges" aria-hidden="true">
            {edges.map((edge) => <PipelineEdge key={`${edge.from}-${edge.to}`} edge={edge} canvas={canvas} />)}
          </svg>
          {graphNodes.map((node) => (
            <article key={node.id} data-node={node.id} className={`pipeline-node pipeline-node--${node.id} pipeline-node--${nodes[node.id]}`}>
              <i aria-hidden="true" />
              <strong>{node.label}</strong>
              <span>{statusLabel(nodes[node.id])}</span>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import {
  apiBaseUrl,
  AuditPhase,
  AuditProgress,
  AuditReport,
  demoReport,
  initialNodes,
  NodeStatus,
  scannerNodeIds,
  SourceKind,
} from "../lib/audit";
import { Pipeline } from "./pipeline";
import { AuditReportView } from "./report";

const savedKey = "shieldscore-access-key";
const sourceTabs: Array<{ value: SourceKind; label: string }> = [
  { value: "github", label: "GitHub" },
  { value: "git", label: "Git URL" },
  { value: "zip", label: "Upload ZIP" },
];

function delay(milliseconds: number) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function isNetworkFailure(error: unknown) {
  return error instanceof TypeError || (error instanceof Error && error.message.includes("Failed to fetch"));
}

function progressNodes(progress: AuditProgress): Record<string, NodeStatus> {
  const next = initialNodes();
  for (const node of progress.nodes) if (node.name in next) next[node.name] = node.status;
  if (progress.status === "running" && next.fan_out === "completed") {
    for (const id of scannerNodeIds) if (next[id] === "pending") next[id] = "running";
  }
  if (scannerNodeIds.every((id) => next[id] === "completed") && next.scanner_merge === "pending") next.scanner_merge = "running";
  if (next.scanner_merge === "completed" && next.compliance_mapper === "pending") next.compliance_mapper = "running";
  if (next.compliance_mapper === "completed" && next.report_generator === "pending") next.report_generator = "running";
  return next;
}

async function apiJson<T>(path: string, init: RequestInit, key: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (key) headers.set("X-API-Key", key);
  const response = await fetch(`${apiBaseUrl}${path}`, { ...init, headers });
  const data = await response.json().catch(() => ({})) as T & { detail?: string; error?: string };
  if (!response.ok) throw new Error(data.detail || data.error || `Request failed with ${response.status}`);
  return data;
}

function ShieldMark() {
  return <span className="brand-mark" aria-hidden="true"><i>✓</i></span>;
}

export function AuditDashboard() {
  const [accessKey, setAccessKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [sourceType, setSourceType] = useState<SourceKind>("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [archive, setArchive] = useState<File | null>(null);
  const [phase, setPhase] = useState<AuditPhase>("idle");
  const [nodes, setNodes] = useState<Record<string, NodeStatus>>(initialNodes);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const runId = useRef(0);
  const timer = useRef<number | null>(null);

  const working = phase === "starting" || phase === "running";
  const locked = working || phase === "checking";
  const hasSource = sourceType === "zip" ? archive !== null : repoUrl.trim().length > 0;
  const canStart = hasSource && accessKey.trim().length > 0 && !locked;

  useEffect(() => {
    const saved = window.sessionStorage.getItem(savedKey);
    const restoreKey = window.setTimeout(() => setAccessKey(saved || ""), 0);
    return () => {
      window.clearTimeout(restoreKey);
      if (timer.current !== null) window.clearInterval(timer.current);
    };
  }, []);

  const stopClock = () => {
    if (timer.current !== null) window.clearInterval(timer.current);
    timer.current = null;
  };

  const reset = () => {
    runId.current += 1;
    stopClock();
    setNodes(initialNodes());
    setReport(null);
    setError(null);
    setElapsed(0);
    setPhase("idle");
  };

  const updateNode = (id: string, status: NodeStatus) => setNodes((current) => ({ ...current, [id]: status }));

  const runDemo = async (id: number) => {
    setPhase("running");
    const play = async (node: string, milliseconds: number) => {
      updateNode(node, "running");
      await delay(milliseconds);
      if (runId.current !== id) return false;
      updateNode(node, "completed");
      return true;
    };
    if (!await play("orchestrator", 420) || !await play("fan_out", 350)) return;
    for (const scanner of scannerNodeIds) updateNode(scanner, "running");
    await delay(700);
    for (const scanner of scannerNodeIds) {
      if (runId.current !== id) return;
      updateNode(scanner, "completed");
      await delay(90);
    }
    if (!await play("scanner_merge", 320) || !await play("compliance_mapper", 360) || !await play("report_generator", 380)) return;
    if (runId.current === id) { setReport(demoReport); setPhase("done"); stopClock(); }
  };

  const pollAudit = async (auditId: string, id: number) => {
    try {
      while (runId.current === id) {
        const progress = await apiJson<AuditProgress>(`/api/audit/${auditId}/status`, {}, accessKey.trim());
        setNodes(progressNodes(progress));
        if (progress.status === "error") throw new Error(progress.error || "The audit did not complete.");
        if (progress.status === "completed") {
          const result = await apiJson<AuditReport>(`/api/audit/${auditId}/results`, {}, accessKey.trim());
          if (runId.current !== id) return;
          setReport(result);
          setPhase("done");
          stopClock();
          return;
        }
        await delay(1000);
      }
    } catch (caught) {
      if (runId.current !== id) return;
      setError(caught instanceof Error ? caught.message : "Audit failed.");
      setPhase("error");
      stopClock();
    }
  };

  const startAudit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const key = accessKey.trim();
    if (!key) { setKeyError("Enter the access key before starting an audit."); return; }
    if (!hasSource) { setError(sourceType === "zip" ? "Choose a .zip file before starting an audit." : "Enter a repository URL before starting an audit."); setPhase("error"); return; }

    const id = runId.current + 1;
    runId.current = id;
    setKeyError(null);
    setError(null);
    setReport(null);
    setNodes(initialNodes());
    setElapsed(0);
    setPhase("checking");
    window.sessionStorage.setItem(savedKey, key);
    const started = Date.now();
    stopClock();
    timer.current = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);

    try {
      await apiJson("/api/audit/status", {}, key);
      if (runId.current !== id) return;
      setPhase("starting");
      const startedAudit = sourceType === "zip"
        ? await apiJson<{ audit_id: string }>("/api/audit/upload", { method: "POST", body: (() => { const data = new FormData(); data.append("file", archive as File); return data; })() }, key)
        : await apiJson<{ audit_id: string }>("/api/audit/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo_url: repoUrl.trim() }) }, key);
      if (runId.current !== id) return;
      setPhase("running");
      void pollAudit(startedAudit.audit_id, id);
    } catch (caught) {
      if (runId.current !== id) return;
      if (isNetworkFailure(caught)) {
        setError("ShieldScore service is unavailable, so this run is showing a local demonstration report.");
        void runDemo(id);
      } else {
        setError(caught instanceof Error ? caught.message : "Audit failed.");
        setPhase("error");
        stopClock();
      }
    }
  };

  const clearKeyOrCancel = () => {
    reset();
    window.sessionStorage.removeItem(savedKey);
    setAccessKey("");
    setKeyError(null);
  };

  return <main className="app-shell">
    <header className="app-header">
      <div className="app-header__top">
        <div className="brand"><ShieldMark /><div><h1>ShieldScore</h1><p>SOC 2 · ISO 27001 · GDPR · DPDP</p></div></div>
        <button type="button" className="clear-button" onClick={clearKeyOrCancel} disabled={!accessKey && !locked}>Clear key</button>
      </div>
      <nav className="source-tabs" aria-label="Repository source type">
        {sourceTabs.map((tab) => <button key={tab.value} type="button" role="tab" aria-selected={sourceType === tab.value} className={sourceType === tab.value ? "is-active" : ""} disabled={locked} onClick={() => { setSourceType(tab.value); setArchive(null); setError(null); }}>{tab.label}</button>)}
      </nav>
      <form className="audit-form" onSubmit={startAudit}>
        <div className="access-row">
          <label htmlFor="access-key">Access key</label>
          <input id="access-key" type="password" value={accessKey} placeholder="Required to run audits" autoComplete="current-password" disabled={locked} onChange={(event) => { setAccessKey(event.target.value); setKeyError(null); }} />
          <span>Access is restricted to control API costs and server usage. Please obtain an access key from Lakshya.</span>
        </div>
        {keyError && <p className="form-error" role="alert">{keyError}</p>}
        <div className="source-input">
          {sourceType === "zip" ? <label className="file-field" htmlFor="archive"><input id="archive" type="file" accept=".zip,application/zip" disabled={locked} onChange={(event) => setArchive(event.target.files?.[0] || null)} /><span>{archive ? archive.name : "Choose a .zip file..."}</span></label> : <input aria-label={sourceType === "github" ? "GitHub repository URL" : "Git repository URL"} type="text" value={repoUrl} disabled={locked} placeholder={sourceType === "github" ? "https://github.com/owner/repo" : "https://gitlab.com/owner/repo or any git URL"} onChange={(event) => setRepoUrl(event.target.value)} />}
          {phase === "checking" ? <button type="button" className="audit-button" disabled>Checking...</button> : working ? <button type="button" className="audit-button audit-button--cancel" onClick={reset}>Cancel</button> : <button type="submit" className="audit-button" disabled={!canStart}>Audit</button>}
        </div>
      </form>
    </header>
    <Pipeline nodes={nodes} elapsed={elapsed} phase={phase} />
    {error && <div className="error-banner" role="alert"><span aria-hidden="true">!</span><p>{error}</p></div>}
    {report && <AuditReportView report={report} />}
    <footer className="app-footer"><span>ShieldScore</span><span>Built by Lakshya</span></footer>
  </main>;
}

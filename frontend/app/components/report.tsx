"use client";

import { useMemo, useState } from "react";
import { AuditFinding, AuditReport, frameworkNames, MappedControl, severityNames, severityOrder, toolNames } from "../lib/audit";

type ReportFinding = { finding: AuditFinding; controls: MappedControl[]; frameworks: string[] };

function scoreTone(score: number) {
  return score >= 80 ? "pass" : score >= 50 ? "warn" : "fail";
}

function findingKey(finding: AuditFinding) {
  return `${finding.tool}|${finding.rule_id || finding.title}|${finding.description}`;
}

function dedupeFindings(report: AuditReport): ReportFinding[] {
  const entries = new Map<string, ReportFinding>();
  for (const [framework, section] of Object.entries(report.frameworks)) {
    for (const mapping of section.findings) {
      const key = findingKey(mapping.finding);
      const entry = entries.get(key) || { finding: mapping.finding, controls: [], frameworks: [] };
      if (!entry.frameworks.includes(framework)) entry.frameworks.push(framework);
      if (!entry.controls.some((control) => control.framework === framework && control.control_id === mapping.control_id)) entry.controls.push(mapping);
      entries.set(key, entry);
    }
  }
  return [...entries.values()].sort((a, b) => severityOrder.indexOf(a.finding.severity) - severityOrder.indexOf(b.finding.severity));
}

function FrameworkScores({ report }: { report: AuditReport }) {
  return <section className="scores" aria-label="Framework scores">
    <p className="eyebrow">Framework scores</p>
    <div className="scores__grid">
      {Object.entries(report.framework_scores).map(([framework, score]) => {
        const controls = report.frameworks[framework]?.controls_triggered || 0;
        return <article className={`score-card score-card--${scoreTone(score)}`} key={framework}>
          <h3>{frameworkNames[framework] || framework.toUpperCase()}</h3>
          <strong>{score}</strong>
          <p>{controls} control{controls === 1 ? "" : "s"} triggered</p>
          <div className="score-card__track"><i style={{ width: `${Math.max(score, 5)}%` }} /></div>
        </article>;
      })}
    </div>
    <div className="overall-score">
      <span>Overall Score</span><strong className={`overall-score--${scoreTone(report.overall_score)}`}>{report.overall_score}</strong><b>/ 100</b>
    </div>
  </section>;
}

function SeverityBreakdown({ report }: { report: AuditReport }) {
  const total = Object.values(report.severity_breakdown).reduce((sum, value) => sum + value, 0);
  const highest = Math.max(...severityOrder.map((severity) => report.severity_breakdown[severity] || 0), 1);
  return <aside className="severity" aria-label="Severity breakdown">
    <p className="eyebrow">Severity breakdown</p>
    <strong className="severity__total">{total} finding{total === 1 ? "" : "s"}</strong>
    <div className="severity__bars">
      {severityOrder.map((severity) => {
        const count = report.severity_breakdown[severity] || 0;
        return <div className={`severity__row severity__row--${severity}`} key={severity}>
          <span><i aria-hidden="true" />{severityNames[severity]}</span>
          <div><b style={{ width: `${count / highest * 100}%` }} /></div>
          <em>{count}</em>
        </div>;
      })}
    </div>
  </aside>;
}

function FindingCard({ entry }: { entry: ReportFinding }) {
  const severity = severityOrder.includes(entry.finding.severity) ? entry.finding.severity : "info";
  return <article className={`finding finding--${severity}`}>
    <header><span className={`badge badge--${severity}`}>{severity.toUpperCase()}</span><span>{toolNames[entry.finding.tool] || entry.finding.tool}</span></header>
    <dl>
      <div><dt>Risk</dt><dd>{entry.finding.title || "—"}</dd></div>
      <div><dt>Impact</dt><dd>{entry.finding.description || "—"}</dd></div>
      <div><dt>Evidence</dt><dd className="finding__mono">{entry.finding.file_path ? <code>{entry.finding.file_path}</code> : <span className="muted">—</span>}</dd></div>
      <div><dt>Controls</dt><dd className="finding__chips">{entry.controls.length ? entry.controls.map((control) => <span key={`${control.framework}:${control.control_id}`} title={control.control_name}><b>{frameworkNames[control.framework] || control.framework}</b>{control.control_id}</span>) : <span className="muted">—</span>}</dd></div>
      {entry.finding.remediation && <div><dt>Remediation</dt><dd>{entry.finding.remediation}</dd></div>}
    </dl>
  </article>;
}

function Findings({ report }: { report: AuditReport }) {
  const [framework, setFramework] = useState("all");
  const [severity, setSeverity] = useState("all");
  const findings = useMemo(() => dedupeFindings(report), [report]);
  const filtered = findings.filter((entry) => (framework === "all" || entry.frameworks.includes(framework)) && (severity === "all" || entry.finding.severity === severity));
  return <section className="findings" aria-label="Audit findings">
    <p className="eyebrow">Findings</p>
    <div className="findings__filters">
      <select aria-label="Filter findings by framework" value={framework} onChange={(event) => setFramework(event.target.value)}>
        <option value="all">All Frameworks</option>
        {Object.keys(frameworkNames).map((key) => <option value={key} key={key}>{frameworkNames[key]}</option>)}
      </select>
      <select aria-label="Filter findings by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
        <option value="all">All Severities</option>
        {severityOrder.map((key) => <option value={key} key={key}>{severityNames[key]}</option>)}
      </select>
      <span>{filtered.length} finding{filtered.length === 1 ? "" : "s"}</span>
    </div>
    <div className="findings__list">
      {filtered.length ? filtered.map((entry) => <FindingCard key={findingKey(entry.finding)} entry={entry} />) : <p className="findings__empty">No findings match the selected filters.</p>}
    </div>
  </section>;
}

export function AuditReportView({ report }: { report: AuditReport }) {
  return <div className="results">
    <FrameworkScores report={report} />
    <div className="results__columns">
      <div>
        <section className="summary"><p className="eyebrow">Executive summary</p><p>{report.executive_summary}</p></section>
        <Findings report={report} />
      </div>
      <SeverityBreakdown report={report} />
    </div>
  </div>;
}

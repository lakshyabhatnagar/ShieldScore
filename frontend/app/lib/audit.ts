export type SourceKind = "github" | "git" | "zip";
export type AuditPhase = "idle" | "checking" | "starting" | "running" | "done" | "error";
export type NodeStatus = "pending" | "running" | "completed" | "error" | "skipped";

export type GraphNode = {
  id: string;
  label: string;
  row: number;
  column: number;
};

export type AuditFinding = {
  tool: string;
  severity: string;
  title: string;
  description: string;
  file_path?: string | null;
  rule_id?: string | null;
  remediation?: string | null;
};

export type MappedControl = {
  finding: AuditFinding;
  framework: string;
  control_id: string;
  control_name: string;
};

export type AuditReport = {
  overall_score: number;
  executive_summary: string;
  framework_scores: Record<string, number>;
  severity_breakdown: Record<string, number>;
  frameworks: Record<string, { controls_triggered: number; findings: MappedControl[] }>;
  error?: string;
};

export type AuditProgress = {
  status: "running" | "completed" | "error";
  error: string | null;
  nodes: Array<{ name: string; status: NodeStatus; error?: string | null }>;
};

export const apiBaseUrl = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export const graphNodes: GraphNode[] = [
  { id: "orchestrator", label: "Orchestrator", row: 1, column: 0 },
  { id: "fan_out", label: "Fan Out", row: 1, column: 1 },
  { id: "semgrep", label: "Semgrep", row: 0, column: 3 },
  { id: "osv", label: "OSV Scanner", row: 1, column: 3 },
  { id: "github", label: "GitHub Checks", row: 2, column: 3 },
  { id: "scan_secrets_pii", label: "Secrets & PII", row: 3, column: 3 },
  { id: "scan_repo_governance", label: "Governance", row: 4, column: 3 },
  { id: "scan_sbom_license", label: "SBOM & License", row: 5, column: 3 },
  { id: "scan_iac_config", label: "IaC Config", row: 6, column: 3 },
  { id: "scan_cicd_security", label: "CI/CD Security", row: 7, column: 3 },
  { id: "scan_data_classification", label: "Data Classification", row: 8, column: 3 },
  { id: "scanner_merge", label: "Scanner Merge", row: 1, column: 6 },
  { id: "compliance_mapper", label: "Compliance Mapper", row: 1, column: 7 },
  { id: "report_generator", label: "Report Generator", row: 1, column: 8 },
];

export const graphEdges = [
  ["orchestrator", "fan_out"],
  ...graphNodes.filter((node) => node.column === 3).map((node) => ["fan_out", node.id]),
  ...graphNodes.filter((node) => node.column === 3).map((node) => [node.id, "scanner_merge"]),
  ["scanner_merge", "compliance_mapper"],
  ["compliance_mapper", "report_generator"],
] as const;

export const scannerNodeIds = graphNodes.filter((node) => node.column === 3).map((node) => node.id);

export function initialNodes(): Record<string, NodeStatus> {
  return Object.fromEntries(graphNodes.map((node) => [node.id, "pending"]));
}

export const frameworkNames: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  gdpr: "GDPR",
  dpdp: "DPDP",
};

export const severityOrder = ["critical", "high", "medium", "low", "info"];

export const severityNames: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const toolNames: Record<string, string> = {
  semgrep: "SAST",
  osv: "OSV",
  github: "GitHub",
  secrets_pii: "Secrets",
  governance: "Governance",
  sbom: "SBOM",
  iac: "IaC",
  cicd: "CI/CD",
  data_classification: "Data Class",
};

const demoFindings: MappedControl[] = [
  {
    framework: "soc2",
    control_id: "CC7.1",
    control_name: "System operations monitoring",
    finding: {
      tool: "semgrep",
      severity: "high",
      title: "Wildcard postMessage target origin",
      description: "The target origin is set to '*', which may expose messages to an unintended window.",
      file_path: "src/components/SharePanel.tsx",
      rule_id: "javascript.browser.security.wildcard-postmessage",
      remediation: "Specify the exact trusted target origin before sending the message.",
    },
  },
  {
    framework: "iso27001",
    control_id: "A.12.6.1",
    control_name: "Management of technical vulnerabilities",
    finding: {
      tool: "semgrep",
      severity: "high",
      title: "Wildcard postMessage target origin",
      description: "The target origin is set to '*', which may expose messages to an unintended window.",
      file_path: "src/components/SharePanel.tsx",
      rule_id: "javascript.browser.security.wildcard-postmessage",
      remediation: "Specify the exact trusted target origin before sending the message.",
    },
  },
  {
    framework: "soc2",
    control_id: "CC6.1",
    control_name: "Logical access controls",
    finding: {
      tool: "secrets_pii",
      severity: "medium",
      title: "Email address found in tracked documentation",
      description: "A personal email pattern was detected in README.md. Public repositories should avoid publishing personal contact data unless it is intentional.",
      file_path: "README.md",
      remediation: "Replace the address with a project contact channel or confirm that publication is intended.",
    },
  },
  {
    framework: "gdpr",
    control_id: "Article 32",
    control_name: "Security of processing",
    finding: {
      tool: "secrets_pii",
      severity: "medium",
      title: "Email address found in tracked documentation",
      description: "A personal email pattern was detected in README.md. Public repositories should avoid publishing personal contact data unless it is intentional.",
      file_path: "README.md",
      remediation: "Replace the address with a project contact channel or confirm that publication is intended.",
    },
  },
  {
    framework: "soc2",
    control_id: "CC8.1",
    control_name: "Change management",
    finding: {
      tool: "github",
      severity: "low",
      title: "Branch protection not detected",
      description: "The default branch does not expose detectable protection rules to the audit token.",
      remediation: "Require pull-request reviews and status checks on the default branch.",
    },
  },
  {
    framework: "iso27001",
    control_id: "A.5.21",
    control_name: "Managing information security in the ICT supply chain",
    finding: {
      tool: "sbom",
      severity: "info",
      title: "Copyleft dependency requires review",
      description: "One dependency carries a copyleft license. Its use should be reviewed against your distribution model.",
      remediation: "Review the license terms with legal counsel before distributing the dependency.",
    },
  },
];

export const demoReport: AuditReport = {
  overall_score: 72,
  executive_summary: "The repository demonstrates a solid baseline for privacy and security controls, but its client-side messaging and public documentation need attention. Two high-risk application findings and two medium-risk data-handling findings should be addressed before a production release. Protecting the default branch and reviewing dependency licensing will improve the remaining control coverage.",
  framework_scores: { soc2: 67, iso27001: 72, gdpr: 82, dpdp: 86 },
  severity_breakdown: { critical: 0, high: 1, medium: 1, low: 1, info: 1 },
  frameworks: {
    soc2: { controls_triggered: 3, findings: demoFindings.filter((item) => item.framework === "soc2") },
    iso27001: { controls_triggered: 2, findings: demoFindings.filter((item) => item.framework === "iso27001") },
    gdpr: { controls_triggered: 1, findings: demoFindings.filter((item) => item.framework === "gdpr") },
    dpdp: { controls_triggered: 0, findings: [] },
  },
};

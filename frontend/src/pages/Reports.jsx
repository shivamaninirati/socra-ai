import { useState, useEffect, useCallback, useRef } from "react";
import {
  FileText, RefreshCw, Shield, AlertTriangle, CheckCircle,
  FileJson, Code, BookOpen, Printer,
  Target, Globe, Hash, Clock, Activity,
  Eye, Check, Brain, FolderSearch, XCircle
} from "lucide-react";
import { useLiveSOC } from "../context/LiveSOCContext";
import api from "../services/api";
import PageHeader from "../components/ui/PageHeader";
import Dropdown from "../components/ui/Dropdown";

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadJSON(data, filename) {
  downloadBlob(JSON.stringify(data, null, 2), filename, "application/json");
}

function downloadMarkdown(data, filename) {
  let md = `# SOCRA AI Enterprise Incident Report\n\n`;
  md += `**Generated:** ${new Date(data.report_metadata?.generated_at || new Date()).toLocaleString("en-GB", { hour12: false })}\n`;
  md += `**Report ID:** ${data.report_metadata?.report_id || "N/A"}\n\n`;
  md += `## Executive Summary\n\n`;
  md += `- **Overall Severity:** ${data.executive_summary?.overall_severity || "N/A"}\n`;
  md += `- **Risk Score:** ${data.executive_summary?.risk_score || 0}/100\n`;
  md += `- **Primary Detection:** ${data.executive_summary?.primary_detection || "N/A"}\n`;
  md += `- **Affected Hosts:** ${data.executive_summary?.affected_hosts || 0}\n`;
  md += `- **Affected Users:** ${data.executive_summary?.affected_users || 0}\n`;
  md += `- **Total Events:** ${data.executive_summary?.total_events || 0}\n\n`;
  md += `## Investigation Statistics\n\n`;
  md += `| Metric | Count |\n|--------|-------|\n`;
  md += `| Critical | ${data.investigation_statistics?.critical || 0} |\n`;
  md += `| High | ${data.investigation_statistics?.high || 0} |\n`;
  md += `| Medium | ${data.investigation_statistics?.medium || 0} |\n`;
  md += `| Low | ${data.investigation_statistics?.low || 0} |\n`;
  md += `| Informational | ${data.investigation_statistics?.informational || 0} |\n\n`;
  if (data.investigation) {
    md += `## Investigation Findings\n\n`;
    md += `- **Investigation ID:** ${data.investigation.id || "N/A"}\n`;
    md += `- **Alert ID:** ${data.investigation.alert_id || "N/A"}\n`;
    md += `- **Status:** ${data.investigation.status || "N/A"}\n`;
    md += `- **Risk Score:** ${data.investigation.risk_score ?? "N/A"}\n`;
    md += `- **Confidence:** ${data.investigation.confidence ?? "N/A"}\n`;
    md += `- **Related Events:** ${data.investigation.related_event_count ?? 0}\n\n`;
    if (data.investigation.notes?.length) {
      md += `### Analyst Notes\n\n`;
      data.investigation.notes.forEach(n => md += `- **[${n.time}]** ${n.note}\n`);
      md += `\n`;
    }
  }
  if (data.resolution) {
    md += `## Resolution\n\n`;
    md += `**Status:** ${data.resolution.status || "N/A"}\n`;
    md += `**Updated:** ${data.resolution.updated_at ? new Date(data.resolution.updated_at).toLocaleString("en-GB", { hour12: false }) : "N/A"}\n\n`;
  }
  md += `## MITRE ATT&CK Mapping\n\n`;
  if (data.mitre_summary?.techniques) {
    Object.entries(data.mitre_summary.techniques).forEach(([tech, count]) => {
      md += `- **${tech}**: ${count} occurrence(s)\n`;
    });
  }
  md += `\n## Indicators of Compromise\n\n`;
  if (data.ioc_summary?.ip_addresses?.length) {
    md += `### IP Addresses\n`;
    data.ioc_summary.ip_addresses.forEach(ip => md += `- \`${ip}\`\n`);
  }
  if (data.ioc_summary?.file_hashes?.length) {
    md += `### File Hashes\n`;
    data.ioc_summary.file_hashes.forEach(h => md += `- \`${h}\`\n`);
  }
  md += `\n## Containment Actions\n\n`;
  (data.containment || []).forEach(action => md += `- ${action}\n`);
  md += `\n## Recovery Actions\n\n`;
  (data.recovery || []).forEach(action => md += `- ${action}\n`);
  md += `\n## Recommendations\n\n`;
  (data.recommendation || []).forEach(rec => md += `- ${rec}\n`);
  if (data.ai_findings?.analysis) {
    md += `\n## AI Findings\n\n${data.ai_findings.analysis}\n`;
  }
  downloadBlob(md, filename, "text/markdown");
}

function downloadIOC(data, filename) {
  let ioc = `# SOCRA AI IOC Export\n`;
  ioc += `# Generated: ${new Date(data.report_metadata?.generated_at || new Date()).toISOString()}\n`;
  ioc += `# Report ID: ${data.report_metadata?.report_id || "N/A"}\n\n`;
  if (data.ioc_summary?.ip_addresses?.length) {
    ioc += `[IP Addresses]\n`;
    data.ioc_summary.ip_addresses.forEach(ip => ioc += `${ip}\n`);
    ioc += `\n`;
  }
  if (data.ioc_summary?.file_hashes?.length) {
    ioc += `[File Hashes]\n`;
    data.ioc_summary.file_hashes.forEach(h => ioc += `${h}\n`);
    ioc += `\n`;
  }
  const allIps = new Set(data.ioc_summary?.ip_addresses || []);
  const allHashes = new Set(data.ioc_summary?.file_hashes || []);
  (data.detections || []).forEach(d => {
    const iocData = d.ioc || {};
    (iocData.ips || []).forEach(ip => allIps.add(ip));
    (iocData.hashes || []).forEach(h => allHashes.add(h));
  });
  if (allIps.size > (data.ioc_summary?.ip_addresses?.length || 0)) {
    ioc += `[Additional IP Addresses from Events]\n`;
    allIps.forEach(ip => {
      if (!(data.ioc_summary?.ip_addresses || []).includes(ip)) ioc += `${ip}\n`;
    });
    ioc += `\n`;
  }
  if (allHashes.size > (data.ioc_summary?.file_hashes?.length || 0)) {
    ioc += `[Additional File Hashes from Events]\n`;
    allHashes.forEach(h => {
      if (!(data.ioc_summary?.file_hashes || []).includes(h)) ioc += `${h}\n`;
    });
    ioc += `\n`;
  }
  downloadBlob(ioc, filename, "text/plain");
}

function Reports() {
  const { analytics } = useLiveSOC();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [generatedAt, setGeneratedAt] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [investigations, setInvestigations] = useState([]);
  const [selectedInvestigation, setSelectedInvestigation] = useState("");
  const [includeAi, setIncludeAi] = useState(false);
  const [scope, setScope] = useState("24h");
  const autoRefreshRef = useRef(false);

  // Real investigation records (persisted) for scoped reports.
  useEffect(() => {
    api.get("/investigations")
      .then((res) => setInvestigations(res.data?.investigations || []))
      .catch(() => setInvestigations([]));
  }, []);

  const generateReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    const params = { limit: 500 };
    if (scope === "7d") {
      const to = new Date();
      const from = new Date(to.getTime() - 7 * 24 * 3600 * 1000);
      params.time_from = from.toISOString();
      params.time_to = to.toISOString();
    }
    if (selectedInvestigation) params.investigation_id = selectedInvestigation;
    if (includeAi) params.include_ai = true;
    try {
      const response = await api.get("/reports/windows", { params });
      const data = response.data;
      if (data?.error && !data.executive_summary) {
        setError(data.error);
      } else {
        setReport(data);
        setGeneratedAt(new Date());
      }
    } catch (e) {
      console.error("Report generation error:", e);
      setError(e?.response?.data?.detail || e?.message || "Failed to generate report.");
    }
    setLoading(false);
  }, [selectedInvestigation, includeAi, scope]);

  useEffect(() => {
    // Deferred so the loading state update is not applied synchronously
    // inside the effect body (react-hooks/set-state-in-effect).
    const timer = setTimeout(() => generateReport(), 0);
    return () => clearTimeout(timer);
  }, [generateReport]);

  const handleExportPDF = () => { window.print(); };

  const handleExportJSON = () => {
    if (!report) return;
    downloadJSON(report, `SOCRA_Report_${Date.now()}.json`);
    setCopiedId("json");
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportIOC = () => {
    if (!report) return;
    downloadIOC(report, `SOCRA_IOC_${Date.now()}.ioc`);
    setCopiedId("ioc");
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportMarkdown = () => {
    if (!report) return;
    downloadMarkdown(report, `SOCRA_Report_${Date.now()}.md`);
    setCopiedId("md");
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Auto-refresh while new alerts stream in (debounced) — report stays current.
  useEffect(() => {
    if (!analytics?.recentAlerts?.length) return;
    if (!report) return;
    if (autoRefreshRef.current) return;
    autoRefreshRef.current = true;
    const timer = setTimeout(() => {
      autoRefreshRef.current = false;
      generateReport();
    }, 5000);
    return () => { clearTimeout(timer); autoRefreshRef.current = false; };
  }, [analytics?.recentAlerts?.length, report, generateReport]);

  const statusStyle = (status) => {
    const s = String(status || "").toLowerCase();
    if (s === "critical") return "bg-red-500/10 text-red-400 border-red-500/30";
    if (s === "high") return "bg-orange-500/10 text-orange-400 border-orange-500/30";
    if (s === "medium") return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    if (s === "contained" || s === "resolved" || s === "closed") return "bg-green-500/10 text-green-400 border-green-500/30";
    return "bg-slate-500/10 text-slate-300 border-slate-500/30";
  };

  if (!report && !error) {
    return (
      <div className="w-full pb-8 space-y-6 select-none">
        <div className="flex justify-between items-center pt-4">
          <PageHeader
            title="Security Reports"
            subtitle="Generate enterprise SOC investigation reports from analyzed Windows security events."
          />
          <button
            onClick={generateReport}
            disabled={loading}
            className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 text-white text-xs font-bold uppercase tracking-wider rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-black/30"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            {loading ? "Generating..." : "Generate Report"}
          </button>
        </div>
        <div className="w-full bg-slate-900/20 border border-slate-800/80 rounded-xl min-h-[55vh] flex items-center justify-center">
          <div className="flex flex-col items-center justify-center py-24">
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-cyan-500 border-t-transparent mb-4"></div>
                <p className="text-cyan-400 text-sm font-semibold">Generating Enterprise Report...</p>
                <p className="text-slate-500 text-xs mt-2">Compiling persisted telemetry, IOCs, and MITRE mapping</p>
              </>
            ) : (
              <>
                <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl mb-4 text-cyan-500/80">
                  <FileText size={28} />
                </div>
                <h2 className="text-sm font-bold text-slate-400 tracking-wider uppercase">No Report Generated</h2>
                <p className="text-xs text-slate-600 max-w-xs mt-2 text-center">
                  Click "Generate Report" to compile forensic data into an enterprise SOC incident report.
                </p>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (error && !report) {
    return (
      <div className="w-full pb-8 space-y-6">
        <div className="flex justify-between items-center pt-4">
          <PageHeader title="Security Reports" subtitle="Generate enterprise SOC investigation reports from analyzed Windows security events." />
          <button onClick={generateReport} className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold uppercase tracking-wider rounded-lg flex items-center gap-2">
            <RefreshCw size={14} /> Retry
          </button>
        </div>
        <div className="p-6 bg-red-500/5 border border-red-500/30 rounded-xl flex items-start gap-3">
          <XCircle size={18} className="text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-bold text-red-400">Report generation failed</p>
            <p className="text-xs text-slate-400 mt-1">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  const meta = report.report_metadata || {};
  const summary = report.executive_summary || {};
  const stats = report.investigation_statistics || {};
  const mitreData = report.mitre_summary || {};
  const iocSummary = report.ioc_summary || {};
  const threat = report.threat_assessment || {};
  const detections = report.detections || [];
  const timeline = report.timeline || [];
  const containment = report.containment || [];
  const recovery = report.recovery || [];
  const recommendations = report.recommendation || [];
  const investigation = report.investigation || null;
  const resolution = report.resolution || null;
  const aiFindings = report.ai_findings || null;

  const totalEvents = summary.total_events || detections.length;

  return (
    <div className="w-full pb-8 space-y-5 select-none printable-area">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pt-4 no-print">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <FileText size={20} className="text-cyan-400" />
              <span>Enterprise SOC Report</span>
            </h1>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[9px] font-black tracking-widest uppercase">
              <span className="w-1 h-1 rounded-full bg-cyan-400" />
              {meta.report_id?.substring(0, 8) || "REPORT"}
            </span>
          </div>
          <p className="text-xs text-slate-500 font-medium mt-1.5">
            Generated {new Date(meta.generated_at || generatedAt || new Date()).toLocaleString("en-GB", { hour12: false })}
            {meta.scope ? ` · ${meta.scope}` : ""}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="min-w-[130px]">
            <Dropdown
              value={scope}
              onChange={setScope}
              options={[{ value: "24h", label: "Last 24h" }, { value: "7d", label: "Last 7 days" }]}
              ariaLabel="Report time scope"
            />
          </div>
          <div className="min-w-[180px] max-w-[220px]">
            <Dropdown
              value={selectedInvestigation}
              onChange={setSelectedInvestigation}
              options={[
                { value: "", label: "Aggregate Report" },
                ...investigations.map((inv) => ({
                  value: inv.id,
                  label: `${inv.id} · ${inv.status} · ${inv.severity || "?"}`,
                })),
              ]}
              ariaLabel="Attach investigation"
            />
          </div>
          <button
            onClick={() => setIncludeAi((v) => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold rounded-lg transition-all border ${
              includeAi
                ? "bg-purple-500/20 border-purple-500/40 text-purple-300"
                : "bg-slate-800/80 border-slate-700/60 text-slate-400"
            }`}
            title="Include AI findings (Ollama) when available"
          >
            <Brain size={12} />
            AI Analysis
          </button>
          <button onClick={generateReport} disabled={loading} className="p-2 bg-slate-800/60 border border-slate-700/60 text-slate-400 hover:text-white rounded-lg transition-all" title="Regenerate">
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          </button>
          <button onClick={handleExportPDF} className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600/80 hover:bg-red-600 text-white text-[10px] font-bold rounded-lg transition-all shadow">
            <Printer size={12} />
            Export PDF
          </button>
          <button onClick={handleExportJSON} className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[10px] font-bold rounded-lg transition-all border border-slate-700/60">
            {copiedId === "json" ? <Check size={12} className="text-green-400" /> : <FileJson size={12} />}
            Export JSON
          </button>
          <button onClick={handleExportIOC} className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[10px] font-bold rounded-lg transition-all border border-slate-700/60">
            {copiedId === "ioc" ? <Check size={12} className="text-green-400" /> : <Hash size={12} />}
            Export IOC
          </button>
          <button onClick={handleExportMarkdown} className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[10px] font-bold rounded-lg transition-all border border-slate-700/60">
            {copiedId === "md" ? <Check size={12} className="text-green-400" /> : <Code size={12} />}
            Export MD
          </button>
        </div>
      </div>

      <div className="space-y-4">
        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
            <Shield size={16} className="text-cyan-400 shrink-0" />
            <h2 className="text-sm font-bold text-slate-200 tracking-wide">Executive Summary</h2>
          </div>
          <div className="p-5">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Severity</p>
                <p className={`text-lg font-black mt-1 ${
                  summary.overall_severity === "Critical" ? "text-red-400" :
                  summary.overall_severity === "High" ? "text-orange-400" :
                  summary.overall_severity === "Medium" ? "text-yellow-400" : "text-green-400"
                }`}>{summary.overall_severity || "N/A"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Risk Score</p>
                <p className="text-lg font-black text-red-400 mt-1">{summary.risk_score || 0}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Events</p>
                <p className="text-lg font-black text-cyan-400 mt-1">{totalEvents}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Hosts</p>
                <p className="text-lg font-black text-slate-300 mt-1">{summary.affected_hosts || 0}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Users</p>
                <p className="text-lg font-black text-slate-300 mt-1">{summary.affected_users || 0}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 text-center">
                <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Processes</p>
                <p className="text-lg font-black text-slate-300 mt-1">{summary.affected_processes || 0}</p>
              </div>
            </div>
            <p className="text-sm text-slate-400 leading-7">
              Primary detection: <span className="text-cyan-400 font-semibold">{summary.primary_detection || "None"}</span>.
              This report covers <span className="text-white font-semibold">{totalEvents}</span> security events
              across <span className="text-white font-semibold">{summary.affected_hosts || 0}</span> hosts
              affecting <span className="text-white font-semibold">{summary.affected_users || 0}</span> users.
              The overall incident severity is <span className={`font-semibold ${
                summary.overall_severity === "Critical" ? "text-red-400" :
                summary.overall_severity === "High" ? "text-orange-400" : "text-yellow-400"
              }`}>{summary.overall_severity || "Unknown"}</span> with a calculated risk score of {summary.risk_score || 0}/100.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <Activity size={16} className="text-amber-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Incident Overview</h2>
            </div>
            <div className="p-5">
              <div className="space-y-2">
                <div className="flex justify-between items-center p-2 bg-slate-900/40 rounded-lg">
                  <span className="text-xs text-slate-400">Severity Distribution</span>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-red-400">C: {stats.critical || 0}</span>
                    <span className="text-orange-400">H: {stats.high || 0}</span>
                    <span className="text-yellow-400">M: {stats.medium || 0}</span>
                    <span className="text-green-400">L: {stats.low || 0}</span>
                    <span className="text-slate-500">I: {stats.informational || 0}</span>
                  </div>
                </div>
                <div className="flex justify-between items-center p-2 bg-slate-900/40 rounded-lg">
                  <span className="text-xs text-slate-400">Affected Hosts</span>
                  <span className="text-xs font-bold text-slate-300">{stats.unique_hosts?.join(", ") || "None"}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-slate-900/40 rounded-lg">
                  <span className="text-xs text-slate-400">Affected Users</span>
                  <span className="text-xs font-bold text-slate-300">{stats.unique_users?.join(", ") || "None"}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-slate-900/40 rounded-lg">
                  <span className="text-xs text-slate-400">Event IDs</span>
                  <span className="text-xs font-bold text-slate-300">{stats.unique_event_ids?.join(", ") || "None"}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-slate-900/40 rounded-lg">
                  <span className="text-xs text-slate-400">Involved Processes</span>
                  <span className="text-xs font-bold text-slate-300">{stats.unique_processes?.slice(0, 5).join(", ") || "None"}{(stats.unique_processes?.length || 0) > 5 ? ` +${stats.unique_processes.length - 5} more` : ""}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <AlertTriangle size={16} className="text-red-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Risk Assessment</h2>
            </div>
            <div className="p-5">
              <div className="flex items-center justify-center gap-6 mb-4">
                <div className="text-center">
                  <div className={`text-4xl font-black ${
                    threat.severity === "Critical" ? "text-red-400" :
                    threat.severity === "High" ? "text-orange-400" :
                    threat.severity === "Medium" ? "text-yellow-400" : "text-green-400"
                  }`}>{threat.risk_score || 0}</div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-1">Risk Score</p>
                </div>
                <div className="text-center">
                  <div className={`text-2xl font-black ${
                    threat.threat_level === "Critical" ? "text-red-400" :
                    threat.threat_level === "High" ? "text-orange-400" : "text-yellow-400"
                  }`}>{threat.threat_level || "Unknown"}</div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-1">Threat Level</p>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-black text-purple-400">{mitreData.total_techniques || 0}</div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-1">MITRE Techniques</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {(investigation || resolution) && (
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <FolderSearch size={16} className="text-cyan-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Investigation Findings & Resolution</h2>
            </div>
            <div className="p-5">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Investigation</p>
                  <p className="text-sm font-black text-cyan-400 mt-1">{investigation?.id || "N/A"}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5 break-all">Alert: {investigation?.alert_id || "N/A"}</p>
                </div>
                <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Status</p>
                  <span className={`inline-block text-[11px] font-bold px-2 py-1 rounded mt-1 border ${statusStyle(resolution?.status || investigation?.status)}`}>
                    {resolution?.status || investigation?.status || "N/A"}
                  </span>
                </div>
                <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Risk / Confidence</p>
                  <p className="text-sm font-black text-red-400 mt-1">{investigation?.risk_score ?? "N/A"}<span className="text-[10px] text-slate-500 font-medium"> / {investigation?.confidence ?? "N/A"} conf.</span></p>
                </div>
                <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold">Related Events</p>
                  <p className="text-sm font-black text-slate-300 mt-1">{investigation?.related_event_count ?? 0}</p>
                </div>
              </div>
              {investigation?.host && (
                <div className="flex flex-wrap gap-2 text-[10px] font-mono text-slate-400 mb-4">
                  <span className="px-2 py-0.5 bg-slate-900/40 rounded border border-slate-800/40">Host: {investigation.host}</span>
                  <span className="px-2 py-0.5 bg-slate-900/40 rounded border border-slate-800/40">User: {investigation.user}</span>
                  <span className="px-2 py-0.5 bg-slate-900/40 rounded border border-slate-800/40">Process: {investigation.process}</span>
                  <span className="px-2 py-0.5 bg-slate-900/40 rounded border border-slate-800/40">Event ID: {investigation.event_id}</span>
                  <span className="px-2 py-0.5 bg-slate-900/40 rounded border border-slate-800/40">MITRE: {investigation.mitre}</span>
                </div>
              )}
              {investigation?.notes?.length > 0 && (
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-2">Analyst Notes</p>
                  <div className="space-y-1.5">
                    {investigation.notes.map((n, idx) => (
                      <div key={idx} className="flex items-start gap-2 p-2 bg-slate-900/40 rounded-lg border border-slate-800/40">
                        <span className="text-[10px] font-mono text-slate-500 w-36 shrink-0">{n.time}</span>
                        <span className="text-xs text-slate-300">{n.note}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {resolution?.updated_at && (
                <p className="text-[10px] text-slate-500 mt-3">
                  Resolution updated: {new Date(resolution.updated_at).toLocaleString("en-GB", { hour12: false })}
                </p>
              )}
            </div>
          </div>
        )}

        {aiFindings && (
          <div className="bg-slate-800/40 border border-purple-700/40 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-purple-700/30 bg-slate-800/60">
              <Brain size={16} className="text-purple-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">AI Findings</h2>
              <span className="ml-auto text-[10px] text-slate-500">{aiFindings.provider} · {aiFindings.model}</span>
            </div>
            <div className="p-5">
              <pre className="text-xs text-slate-300 leading-6 whitespace-pre-wrap font-sans">{aiFindings.analysis}</pre>
            </div>
          </div>
        )}

        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
            <Clock size={16} className="text-cyan-400 shrink-0" />
            <h2 className="text-sm font-bold text-slate-200 tracking-wide">Attack Timeline</h2>
            <span className="ml-auto text-[10px] text-slate-500">{timeline.length} events</span>
          </div>
          <div className="p-5 max-h-64 overflow-y-auto">
            {timeline.length === 0 ? (
              <p className="text-slate-500 text-xs text-center py-4">No timeline events available.</p>
            ) : (
              <div className="space-y-1">
                {timeline.map((entry, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-2 bg-slate-900/30 rounded-lg border border-slate-800/30">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
                    <span className="text-[10px] font-mono text-slate-500 w-20 shrink-0">
                      {entry.time ? new Date(entry.time).toLocaleTimeString("en-GB", { hour12: false }) : "N/A"}
                    </span>
                    <span className="text-[11px] font-mono text-cyan-500 w-12 shrink-0">{entry.event_id || "-"}</span>
                    <span className="text-[11px] text-slate-400 truncate">{entry.process || "N/A"}</span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ml-auto shrink-0 ${
                      (entry.severity || "").toLowerCase() === "critical" ? "bg-red-500/10 text-red-400" :
                      (entry.severity || "").toLowerCase() === "high" ? "bg-orange-500/10 text-orange-400" :
                      (entry.severity || "").toLowerCase() === "medium" ? "bg-yellow-500/10 text-yellow-400" :
                      "bg-green-500/10 text-green-400"
                    }`}>{entry.severity || "Info"}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <Target size={16} className="text-purple-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">MITRE ATT&CK Mapping</h2>
            </div>
            <div className="p-5">
              {Object.keys(mitreData.techniques || {}).length === 0 ? (
                <p className="text-slate-500 text-xs text-center py-4">No MITRE techniques identified.</p>
              ) : (
                <div className="space-y-2">
                  {Object.entries(mitreData.techniques || {}).map(([techId, count]) => (
                    <div key={techId} className="flex items-center justify-between p-2 bg-slate-900/40 rounded-lg border border-slate-800/40">
                      <span className="text-xs font-mono font-bold text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded">{techId}</span>
                      <span className="text-xs text-slate-400">{count} occurrence{count !== 1 ? "s" : ""}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <Globe size={16} className="text-green-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Indicators of Compromise</h2>
            </div>
            <div className="p-5 max-h-64 overflow-y-auto">
              {(iocSummary.ip_addresses?.length === 0 && iocSummary.file_hashes?.length === 0) ? (
                <p className="text-slate-500 text-xs text-center py-4">No IOCs identified.</p>
              ) : (
                <div className="space-y-3">
                  {iocSummary.ip_addresses?.length > 0 && (
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 mb-1.5">IP Addresses ({iocSummary.total_ips || iocSummary.ip_addresses.length})</p>
                      <div className="flex flex-wrap gap-1.5">
                        {iocSummary.ip_addresses.map((ip, idx) => (
                          <span key={idx} className="text-[10px] font-mono text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">{ip}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {iocSummary.file_hashes?.length > 0 && (
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-green-400 mb-1.5">File Hashes ({iocSummary.total_hashes || iocSummary.file_hashes.length})</p>
                      <div className="space-y-1">
                        {iocSummary.file_hashes.map((hash, idx) => (
                          <div key={idx} className="text-[10px] font-mono text-green-300 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded break-all">{hash}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
            <Eye size={16} className="text-amber-400 shrink-0" />
            <h2 className="text-sm font-bold text-slate-200 tracking-wide">Evidence Log</h2>
            <span className="ml-auto text-[10px] text-slate-500">{detections.length} detections</span>
          </div>
          <div className="p-5 max-h-72 overflow-y-auto">
            {detections.length === 0 ? (
              <p className="text-slate-500 text-xs text-center py-4">No detection evidence available.</p>
            ) : (
              <div className="space-y-2">
                {detections.slice(0, 50).map((d, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-cyan-500 font-bold">{d.event_id || "-"}</span>
                      <span className="text-slate-400">|</span>
                      <span className="text-slate-300 font-medium">{d.detection || "Unknown"}</span>
                      {d.host && <span className="text-slate-500">| {d.host}</span>}
                      <span className={`ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        d.severity === "Critical" ? "bg-red-500/10 text-red-400" :
                        d.severity === "High" ? "bg-orange-500/10 text-orange-400" :
                        d.severity === "Medium" ? "bg-yellow-500/10 text-yellow-400" : "bg-slate-500/10 text-slate-400"
                      }`}>{d.severity || "Info"}</span>
                    </div>
                    {d.description && <p className="text-[10px] text-slate-500 mt-1.5 leading-5">{d.description}</p>}
                  </div>
                ))}
                {detections.length > 50 && (
                  <p className="text-[10px] text-slate-600 text-center py-2">+{detections.length - 50} more detections (showing first 50)</p>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <Shield size={16} className="text-red-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Containment Actions</h2>
              <span className="ml-auto text-[10px] text-slate-500">{containment.length} actions</span>
            </div>
            <div className="p-5">
              {containment.length === 0 ? (
                <p className="text-slate-500 text-xs text-center py-4">No containment actions derived from matched detection rules.</p>
              ) : (
                <ul className="space-y-2">
                  {containment.map((action, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                      <span className="w-5 h-5 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center shrink-0 text-[10px] font-black">{idx + 1}</span>
                      <span className="text-xs text-slate-300">{action}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
              <CheckCircle size={16} className="text-green-400 shrink-0" />
              <h2 className="text-sm font-bold text-slate-200 tracking-wide">Recovery Actions</h2>
              <span className="ml-auto text-[10px] text-slate-500">{recovery.length} actions</span>
            </div>
            <div className="p-5">
              {recovery.length === 0 ? (
                <p className="text-slate-500 text-xs text-center py-4">No recovery actions derived from matched detection rules.</p>
              ) : (
                <ul className="space-y-2">
                  {recovery.map((action, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                      <CheckCircle size={14} className="text-green-400 shrink-0 mt-0.5" />
                      <span className="text-xs text-slate-300">{action}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
            <BookOpen size={16} className="text-cyan-400 shrink-0" />
            <h2 className="text-sm font-bold text-slate-200 tracking-wide">Recommendations</h2>
            <span className="ml-auto text-[10px] text-slate-500">{recommendations.length} from matched rules</span>
          </div>
          <div className="p-5">
            {recommendations.length === 0 ? (
              <p className="text-slate-500 text-xs text-center py-4">No recommendations derived from matched detection rules.</p>
            ) : (
              <div className="space-y-3">
                {recommendations.map((rec, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                    <div className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0 text-xs font-black">{idx + 1}</div>
                    <p className="text-xs font-bold text-slate-200 leading-5">{rec}</p>
                  </div>
                ))}
              </div>
            )}

            {report.final_verdict && (
              <div className={`mt-4 p-4 rounded-lg border ${
                (report.final_verdict.status || "").toLowerCase() === "critical" ? "bg-red-500/5 border-red-500/20" :
                (report.final_verdict.status || "").toLowerCase() === "high" ? "bg-orange-500/5 border-orange-500/20" :
                (report.final_verdict.status || "").toLowerCase() === "medium" ? "bg-yellow-500/5 border-yellow-500/20" :
                "bg-green-500/5 border-green-500/20"
              }`}>
                <div className="flex items-center gap-2 mb-2">
                  <FileText size={14} className="text-slate-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Analyst Verdict</span>
                  {report.final_verdict.status && (
                    <span className={`ml-auto text-[10px] font-bold px-2 py-0.5 rounded border ${statusStyle(report.final_verdict.status)}`}>
                      {report.final_verdict.status}
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-300 leading-7">{report.final_verdict.summary || "No verdict available."}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <style dangerouslySetInnerHTML={{__html: `
        @media print {
          .no-print { display: none !important; }
          .printable-area { background: white !important; color: black !important; }
          body { background: white !important; }
          ::-webkit-scrollbar { display: none !important; }
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
        .animate-fadeIn { animation: fadeIn 0.15s ease-out forwards; }
      `}} />
    </div>
  );
}

export default Reports;

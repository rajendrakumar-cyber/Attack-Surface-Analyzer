import React, { useState, useEffect, useRef } from "react";
import { io, Socket } from "socket.io-client";
import { 
  Shield, 
  Search, 
  Activity, 
  AlertTriangle, 
  Globe, 
  Server, 
  ChevronRight, 
  FileText, 
  LayoutDashboard,
  Zap,
  Lock,
  Terminal,
  BarChart3
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  Tooltip as RechartsTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from "recharts";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ScanResult {
  host: string;
  openPorts: number[];
}

interface Risk {
  title: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  impact: string;
  remediation: string;
  host?: string;
  cveId?: string;
  nvdLink?: string;
  cvssScore?: number;
}

interface Analysis {
  risks: Risk[];
  summary: string;
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [discoveredSubdomains, setDiscoveredSubdomains] = useState<string[]>([]);
  const [discoveredServices, setDiscoveredServices] = useState<{host: string, port: number}[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [attackPaths, setAttackPaths] = useState<string>("");
  const [socket, setSocket] = useState<Socket | null>(null);
  const [activeTab, setActiveTab] = useState<"dashboard" | "assets" | "risks" | "report" | "history">("dashboard");
  const [history, setHistory] = useState<{id: string, domain: string, timestamp: string}[]>([]);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  useEffect(() => {
    const newSocket = io();
    setSocket(newSocket);

    newSocket.on("scan:progress", (data) => {
      setProgress(data.progress);
      setStatusMessage(data.message);
    });

    newSocket.on("scan:update", (data) => {
      if (data.type === "subdomain") {
        setDiscoveredSubdomains(prev => [...prev, data.value]);
      } else if (data.type === "service") {
        setDiscoveredServices(prev => [...prev, { host: data.host, port: data.port }]);
      }
    });

    newSocket.on("scan:complete", (data) => {
      setAnalysis(data.analysis);
      setAttackPaths(data.attackPaths);
      setDiscoveredSubdomains(data.subdomains);
      setDiscoveredServices(data.services);
      setCurrentScanId(data.id);
      setIsScanning(false);
      setProgress(100);
      setStatusMessage("Scan complete.");
    });

    newSocket.on("scan:error", (data) => {
      setStatusMessage(`Error: ${data.message}`);
      setIsScanning(false);
    });

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch("/api/scans");
      const data = await response.json();
      setHistory(data);
    } catch (error) {
      console.error("Failed to fetch history", error);
    }
  };

  const loadScan = async (id: string) => {
    try {
      const response = await fetch(`/api/scans/${id}`);
      const data = await response.json();
      setAnalysis(data.analysis);
      setAttackPaths(data.attack_paths);
      setDiscoveredSubdomains(data.discovered_subdomains);
      setDiscoveredServices(data.discovered_services);
      setDomain(data.domain);
      setCurrentScanId(data.id);
      setActiveTab("dashboard");
    } catch (error) {
      console.error("Failed to load scan", error);
    }
  };

  useEffect(() => {
    if (activeTab === "history") {
      fetchHistory();
    }
  }, [activeTab]);

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain || !socket) return;

    setIsScanning(true);
    setProgress(0);
    setStatusMessage("Initializing...");
    setDiscoveredSubdomains([]);
    setDiscoveredServices([]);
    setAnalysis(null);
    setAttackPaths("");
    setActiveTab("dashboard");

    socket.emit("scan:start", { domain });
  };

  const severityColors = {
    Low: "#10b981",
    Medium: "#f59e0b",
    High: "#ef4444",
    Critical: "#7f1d1d"
  };

  const riskData = analysis?.risks.reduce((acc: any, risk) => {
    acc[risk.severity] = (acc[risk.severity] || 0) + 1;
    return acc;
  }, {});

  const pieData = riskData ? Object.entries(riskData).map(([name, value]) => ({ name, value })) : [];

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-zinc-100 font-sans selection:bg-emerald-500/30">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 border-r border-zinc-800 bg-[#0d0d0d] z-20 hidden lg:block">
        <div className="p-6 flex items-center gap-3 border-b border-zinc-800">
          <div className="w-10 h-10 bg-emerald-500 rounded-xl flex items-center justify-center shadow-[0_0_20px_rgba(16,185,129,0.2)]">
            <Shield className="text-black w-6 h-6" />
          </div>
          <span className="font-bold text-xl tracking-tight">AEGIS</span>
        </div>

        <nav className="p-4 space-y-2">
          {[
            { id: "dashboard", icon: LayoutDashboard, label: "Dashboard" },
            { id: "assets", icon: Globe, label: "Assets" },
            { id: "risks", icon: AlertTriangle, label: "Risks" },
            { id: "report", icon: FileText, label: "Report" },
            { id: "history", icon: Activity, label: "History" },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as any)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200",
                activeTab === item.id 
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"
              )}
            >
              <item.icon className="w-5 h-5" />
              <span className="font-medium">{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="absolute bottom-0 left-0 w-full p-6 border-t border-zinc-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center">
              <Lock className="w-4 h-4 text-zinc-400" />
            </div>
            <div>
              <p className="text-xs font-bold text-zinc-300 uppercase tracking-wider">System Status</p>
              <p className="text-[10px] text-emerald-500 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Operational
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="lg:ml-64 p-8 min-h-screen">
        {/* Header */}
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
          <div>
            <h1 className="text-4xl font-bold tracking-tight mb-2">Attack Surface Analyzer</h1>
            <p className="text-zinc-500">Map, scan, and prioritize external security risks with AI.</p>
          </div>

          <form onSubmit={handleStartScan} className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-500" />
              <input
                type="text"
                placeholder="Enter domain (e.g., example.com)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={isScanning}
                className="bg-zinc-900 border border-zinc-800 rounded-xl pl-12 pr-4 py-3 w-72 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 transition-all disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !domain}
              className="bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-800 text-black font-bold px-6 py-3 rounded-xl transition-all shadow-lg shadow-emerald-500/10 flex items-center gap-2"
            >
              {isScanning ? (
                <Activity className="w-5 h-5 animate-spin" />
              ) : (
                <Zap className="w-5 h-5" />
              )}
              {isScanning ? "Scanning..." : "Start Scan"}
            </button>
          </form>
        </header>

        {/* Progress Bar */}
        {isScanning && (
          <div className="mb-12">
            <div className="flex justify-between items-end mb-2">
              <p className="text-sm font-medium text-emerald-400 flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                {statusMessage}
              </p>
              <p className="text-sm font-bold text-zinc-400">{progress}%</p>
            </div>
            <div className="h-2 bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
              <motion.div 
                className="h-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
          </div>
        )}

        <AnimatePresence mode="wait">
          {activeTab === "dashboard" && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-8"
            >
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {[
                  { label: "Discovered Subdomains", value: discoveredSubdomains.length, icon: Globe, color: "text-blue-400" },
                  { label: "Active Services", value: discoveredServices.length, icon: Server, color: "text-purple-400" },
                  { label: "Total Risks", value: analysis?.risks.length || 0, icon: AlertTriangle, color: "text-red-400" },
                  { label: "Critical Risks", value: analysis?.risks.filter(r => r.severity === "Critical").length || 0, icon: Shield, color: "text-rose-600" },
                ].map((stat, i) => (
                  <div key={i} className="bg-[#0d0d0d] border border-zinc-800 p-6 rounded-2xl">
                    <div className="flex justify-between items-start mb-4">
                      <div className={cn("p-3 rounded-xl bg-zinc-900 border border-zinc-800", stat.color)}>
                        <stat.icon className="w-6 h-6" />
                      </div>
                    </div>
                    <p className="text-zinc-500 text-sm font-medium uppercase tracking-wider">{stat.label}</p>
                    <p className="text-3xl font-bold mt-1">{stat.value}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Risk Distribution Chart */}
                <div className="lg:col-span-1 bg-[#0d0d0d] border border-zinc-800 p-8 rounded-2xl">
                  <h3 className="text-xl font-bold mb-8 flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-emerald-500" />
                    Risk Distribution
                  </h3>
                  <div className="h-64">
                    {pieData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={pieData}
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {pieData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={severityColors[entry.name as keyof typeof severityColors]} />
                            ))}
                          </Pie>
                          <RechartsTooltip 
                            contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a', borderRadius: '8px' }}
                            itemStyle={{ color: '#fff' }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-zinc-600 italic">
                        No scan data available
                      </div>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-4 mt-8">
                    {Object.entries(severityColors).map(([name, color]) => (
                      <div key={name} className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-sm text-zinc-400">{name}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recent Activity / Feed */}
                <div className="lg:col-span-2 bg-[#0d0d0d] border border-zinc-800 p-8 rounded-2xl">
                  <h3 className="text-xl font-bold mb-8 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-emerald-500" />
                    Live Discovery Feed
                  </h3>
                  <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                    {discoveredSubdomains.length === 0 && discoveredServices.length === 0 && (
                      <div className="text-center py-12 text-zinc-600 italic">
                        Start a scan to see live discovery results
                      </div>
                    )}
                    {discoveredSubdomains.map((sub, i) => (
                      <div key={`sub-${i}`} className="flex items-center gap-4 p-4 bg-zinc-900/50 border border-zinc-800/50 rounded-xl">
                        <div className="w-2 h-2 rounded-full bg-blue-500" />
                        <div className="flex-1">
                          <p className="text-sm font-bold text-zinc-200">Subdomain Discovered</p>
                          <p className="text-xs text-zinc-500 font-mono">{sub}</p>
                        </div>
                        <Globe className="w-4 h-4 text-zinc-600" />
                      </div>
                    ))}
                    {discoveredServices.map((svc, i) => (
                      <div key={`svc-${i}`} className="flex items-center gap-4 p-4 bg-zinc-900/50 border border-zinc-800/50 rounded-xl">
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <div className="flex-1">
                          <p className="text-sm font-bold text-zinc-200">Service Detected</p>
                          <p className="text-xs text-zinc-500 font-mono">{svc.host}:{svc.port}</p>
                        </div>
                        <Server className="w-4 h-4 text-zinc-600" />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "assets" && (
            <motion.div 
              key="assets"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="bg-[#0d0d0d] border border-zinc-800 rounded-2xl overflow-hidden"
            >
              <div className="p-8 border-b border-zinc-800">
                <h2 className="text-2xl font-bold">Discovered Assets</h2>
                <p className="text-zinc-500">Inventory of all subdomains and exposed services.</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-zinc-900/50 text-zinc-400 text-xs uppercase tracking-wider">
                      <th className="px-8 py-4 font-bold">Host / Subdomain</th>
                      <th className="px-8 py-4 font-bold">Status</th>
                      <th className="px-8 py-4 font-bold">Open Ports</th>
                      <th className="px-8 py-4 font-bold">Risk Level</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {discoveredSubdomains.map((sub, i) => {
                      const services = discoveredServices.filter(s => s.host === sub);
                      const hostRisks = analysis?.risks.filter(r => r.host === sub);
                      const maxSeverity = hostRisks?.length ? hostRisks.sort((a, b) => {
                        const order = { Critical: 3, High: 2, Medium: 1, Low: 0 };
                        return order[b.severity] - order[a.severity];
                      })[0].severity : "None";

                      return (
                        <tr key={i} className="hover:bg-zinc-800/30 transition-colors">
                          <td className="px-8 py-6 font-mono text-sm text-zinc-300">{sub}</td>
                          <td className="px-8 py-6">
                            <span className="px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-500 text-[10px] font-bold uppercase tracking-widest border border-emerald-500/20">
                              Active
                            </span>
                          </td>
                          <td className="px-8 py-6">
                            <div className="flex flex-wrap gap-2">
                              {services.length > 0 ? services.map((s, j) => (
                                <span key={j} className="px-2 py-1 rounded bg-zinc-800 text-zinc-400 text-xs font-mono">
                                  {s.port}
                                </span>
                              )) : (
                                <span className="text-zinc-600 text-xs italic">No open ports found</span>
                              )}
                            </div>
                          </td>
                          <td className="px-8 py-6">
                            <span 
                              className="text-xs font-bold"
                              style={{ color: severityColors[maxSeverity as keyof typeof severityColors] || "#52525b" }}
                            >
                              {maxSeverity}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === "risks" && (
            <motion.div 
              key="risks"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-6"
            >
              <div className="flex justify-between items-end mb-4">
                <div>
                  <h2 className="text-2xl font-bold">Vulnerability Analysis</h2>
                  <p className="text-zinc-500">AI-prioritized security risks and misconfigurations.</p>
                </div>
              </div>

              {!analysis ? (
                <div className="bg-[#0d0d0d] border border-zinc-800 p-20 rounded-2xl text-center">
                  <AlertTriangle className="w-12 h-12 text-zinc-700 mx-auto mb-4" />
                  <p className="text-zinc-500 italic">Run a scan to analyze potential vulnerabilities</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-6">
                  {analysis.risks.map((risk, i) => (
                    <div key={i} className="bg-[#0d0d0d] border border-zinc-800 rounded-2xl overflow-hidden">
                      <div className="flex flex-col md:flex-row">
                        <div 
                          className="w-2 shrink-0" 
                          style={{ backgroundColor: severityColors[risk.severity] }}
                        />
                        <div className="p-8 flex-1">
                          <div className="flex justify-between items-start mb-4">
                            <div>
                              <div className="flex items-center gap-3 mb-2">
                                <span 
                                  className="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest border"
                                  style={{ 
                                    color: severityColors[risk.severity],
                                    borderColor: `${severityColors[risk.severity]}40`,
                                    backgroundColor: `${severityColors[risk.severity]}10`
                                  }}
                                >
                                  {risk.severity}
                                </span>
                                {risk.host && (
                                  <span className="text-xs font-mono text-zinc-500">{risk.host}</span>
                                )}
                              </div>
                              <h3 className="text-xl font-bold">{risk.title}</h3>
                            </div>
                            {risk.cvssScore !== undefined && (
                              <div className="text-right">
                                <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">CVSS Score</p>
                                <p className="text-2xl font-black text-zinc-100">{risk.cvssScore.toFixed(1)}</p>
                              </div>
                            )}
                          </div>

                          {risk.cveId && (
                            <div className="mb-6 flex items-center gap-3">
                              <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-800 rounded-lg border border-zinc-700">
                                <Shield className="w-3.5 h-3.5 text-emerald-500" />
                                <span className="text-xs font-bold text-zinc-300">{risk.cveId}</span>
                              </div>
                              {risk.nvdLink && (
                                <a 
                                  href={risk.nvdLink} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1 transition-colors"
                                >
                                  View on NVD
                                  <ChevronRight className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                          )}
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-6">
                            <div>
                              <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">Impact</h4>
                              <p className="text-sm text-zinc-300 leading-relaxed">{risk.impact}</p>
                            </div>
                            <div>
                              <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-2">Remediation</h4>
                              <p className="text-sm text-zinc-300 leading-relaxed">{risk.remediation}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {activeTab === "history" && (
            <motion.div 
              key="history"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="bg-[#0d0d0d] border border-zinc-800 rounded-2xl overflow-hidden"
            >
              <div className="p-8 border-b border-zinc-800">
                <h2 className="text-2xl font-bold">Scan History</h2>
                <p className="text-zinc-500">View and compare historical attack surface data.</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-zinc-900/50 text-zinc-400 text-xs uppercase tracking-wider">
                      <th className="px-8 py-4 font-bold">Domain</th>
                      <th className="px-8 py-4 font-bold">Scan ID</th>
                      <th className="px-8 py-4 font-bold">Timestamp</th>
                      <th className="px-8 py-4 font-bold">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {history.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="px-8 py-12 text-center text-zinc-600 italic">
                          No historical scans found
                        </td>
                      </tr>
                    ) : (
                      history.map((scan) => (
                        <tr key={scan.id} className="hover:bg-zinc-800/30 transition-colors">
                          <td className="px-8 py-6 font-bold text-zinc-200">{scan.domain}</td>
                          <td className="px-8 py-6 font-mono text-sm text-zinc-400">{scan.id}</td>
                          <td className="px-8 py-6 text-sm text-zinc-500">
                            {new Date(scan.timestamp).toLocaleString()}
                          </td>
                          <td className="px-8 py-6">
                            <button 
                              onClick={() => loadScan(scan.id)}
                              className="text-emerald-500 hover:text-emerald-400 font-bold text-sm flex items-center gap-1 transition-colors"
                            >
                              Load Report
                              <ChevronRight className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === "report" && (
            <motion.div 
              key="report"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              className="bg-white text-zinc-900 p-12 md:p-20 rounded-2xl shadow-2xl max-w-4xl mx-auto"
            >
              <div className="flex justify-between items-start border-b-2 border-zinc-100 pb-12 mb-12">
                <div>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-8 h-8 bg-emerald-600 rounded-lg flex items-center justify-center">
                      <Shield className="text-white w-5 h-5" />
                    </div>
                    <span className="font-bold text-xl tracking-tight text-zinc-900">AEGIS</span>
                  </div>
                  <h1 className="text-4xl font-black uppercase tracking-tighter">Security Assessment</h1>
                  <p className="text-zinc-500 font-medium mt-1">Target: {domain || "N/A"}</p>
                </div>
                <div className="text-right">
                  <p className="text-xs font-bold text-zinc-400 uppercase tracking-widest mb-1">Report ID</p>
                  <p className="font-mono text-sm">{currentScanId || "N/A"}</p>
                  <p className="text-xs text-zinc-400 mt-2">{new Date().toLocaleDateString()}</p>
                </div>
              </div>

              {!analysis ? (
                <div className="py-20 text-center text-zinc-400 italic">
                  Complete a scan to generate a full security report
                </div>
              ) : (
                <div className="space-y-12">
                  <section>
                    <h2 className="text-lg font-black uppercase tracking-widest border-b border-zinc-100 pb-2 mb-6">Executive Summary</h2>
                    <p className="text-zinc-700 leading-relaxed whitespace-pre-wrap">{analysis.summary}</p>
                  </section>

                  <section>
                    <h2 className="text-lg font-black uppercase tracking-widest border-b border-zinc-100 pb-2 mb-6">Attack Path Analysis</h2>
                    <div className="bg-zinc-50 p-8 rounded-xl border border-zinc-100">
                      <div className="prose prose-zinc max-w-none text-sm text-zinc-700 leading-relaxed whitespace-pre-wrap">
                        {attackPaths}
                      </div>
                    </div>
                  </section>

                  <section>
                    <h2 className="text-lg font-black uppercase tracking-widest border-b border-zinc-100 pb-2 mb-6">Risk Prioritization</h2>
                    <div className="space-y-4">
                      {analysis.risks.sort((a, b) => {
                        const order = { Critical: 3, High: 2, Medium: 1, Low: 0 };
                        return order[b.severity] - order[a.severity];
                      }).map((risk, i) => (
                        <div key={i} className="flex gap-6 p-6 border border-zinc-100 rounded-xl">
                          <div className="w-24 shrink-0">
                            <span 
                              className="text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded"
                              style={{ 
                                backgroundColor: `${severityColors[risk.severity]}15`,
                                color: severityColors[risk.severity]
                              }}
                            >
                              {risk.severity}
                            </span>
                          </div>
                          <div>
                            <div className="flex justify-between items-start mb-2">
                              <h3 className="font-bold text-zinc-900">{risk.title}</h3>
                              {risk.cvssScore !== undefined && (
                                <span className="text-xs font-bold text-zinc-400">CVSS: {risk.cvssScore.toFixed(1)}</span>
                              )}
                            </div>
                            {risk.cveId && (
                              <p className="text-[10px] font-bold text-emerald-600 mb-2">{risk.cveId}</p>
                            )}
                            <p className="text-sm text-zinc-600 leading-relaxed">{risk.impact}</p>
                            <div className="mt-4 pt-4 border-t border-zinc-50">
                              <p className="text-[10px] font-black uppercase tracking-widest text-zinc-400 mb-1">Recommended Fix</p>
                              <p className="text-sm text-zinc-700">{risk.remediation}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>

                  <div className="pt-12 border-t border-zinc-100 text-center">
                    <p className="text-[10px] text-zinc-400 uppercase tracking-[0.2em] font-bold">Confidential - Aegis Attack Surface Analyzer</p>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #27272a;
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #3f3f46;
        }
      `}</style>
    </div>
  );
}

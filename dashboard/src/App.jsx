import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield, AlertTriangle, Clock, Activity, Lock, ShieldCheck,
  ShieldAlert as AlertIcon, Zap, ArrowRight, RefreshCw,
  Database, Terminal, FileText, Settings, Save,
  Maximize2, ChevronRight, BarChart3, Fingerprint, Network, Globe2
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  PieChart, Pie, Cell, Tooltip as ChartTooltip, ResponsiveContainer
} from 'recharts';

const API_BASE = "http://localhost:8000";

// --- Google Material Design 3 Components ---

const GoogleCard = ({ children, className = "" }) => (
  <div className={`google-card ${className}`}>
    {children}
  </div>
);

const StatPill = ({ icon, label, value, color }) => {
  const IconComponent = icon;
  return (
    <GoogleCard className="p-7 flex items-center space-x-6">
      <div className={`p-4.5 rounded-[20px] ${color.replace('text-', 'bg-')}/10 ${color}`}>
        <IconComponent className="w-7 h-7" />
      </div>
      <div>
        <p className="text-[10px] font-black text-white/30 uppercase tracking-[0.25em] leading-none mb-2">{label}</p>
        <p className="text-3xl font-bold tracking-tight text-white">{value}</p>
      </div>
    </GoogleCard>
  );
};

const HistoryRow = ({ item, onClick }) => {
  const isMalicious = item.report?.is_malicious;
  return (
    <div onClick={onClick} className="flex items-center justify-between px-8 py-7 hover:bg-white/[0.04] transition-all cursor-pointer border-b border-white/[0.03] group">
      <div className="flex items-center space-x-8 min-w-0">
        <div className="relative">
          <div className={`w-3.5 h-3.5 rounded-full ${isMalicious ? 'bg-google-red shadow-[0_0_15px_rgba(234,67,53,0.5)] animate-pulse' : 'bg-google-green shadow-[0_0_10px_rgba(52,168,83,0.3)]'}`} />
        </div>
        <div className="min-w-0 space-y-1">
          <p className="text-[15px] font-medium truncate text-[#E8EAED] group-hover:text-google-blue transition-colors">{item.url}</p>
          <div className="flex items-center space-x-3 opacity-40">
            <span className="text-[10px] font-black uppercase tracking-widest">
              {isMalicious ? 'Threat Neutralized' : 'Asset Secure'}
            </span>
            <span className="text-white/20 font-black text-[8px] tracking-widest">•</span>
            <span className="text-[10px] uppercase font-bold tracking-wider">
              {item.report?.geo?.isp?.split(' ')[0] || 'Resolving'} • {item.report?.geo?.country || 'Cloud'}
            </span>
          </div>
        </div>
      </div>
      <ChevronRight className="w-5 h-5 text-white/10 group-hover:text-white/50 group-hover:translate-x-1 transition-all" />
    </div>
  );
};

const Modal = ({ isOpen, onClose, children, title }) => {
  const MotionDiv = motion.div;
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 md:p-12 overflow-hidden">
          <MotionDiv initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="absolute inset-0 bg-black/90 backdrop-blur-2xl" onClick={onClose} />
          <MotionDiv initial={{ scale: 0.96, opacity: 0, y: 20 }} animate={{ scale: 1, opacity: 1, y: 0 }} exit={{ scale: 0.96, opacity: 0, y: 20 }} className="relative bg-[#171717] border border-white/10 rounded-[44px] shadow-2xl max-w-6xl w-full max-h-[92vh] overflow-hidden flex flex-col">
            <div className="px-10 py-8 border-b border-white/5 flex items-center justify-between bg-white/[0.01]">
              <div className="space-y-1">
                <h3 className="text-xl font-bold text-white tracking-tight leading-none uppercase tracking-[0.2em]">{title}</h3>
                <div className="h-1 w-12 bg-google-blue rounded-full" />
              </div>
              <button onClick={onClose} className="p-3 hover:bg-white/10 rounded-full transition-all text-white/30 hover:text-white">
                <RefreshCw className="w-5 h-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto custom-scrollbar">
              {children}
            </div>
          </MotionDiv>
        </div>
      )}
    </AnimatePresence>
  );
};

const DetailWidget = ({ icon, label, value, sub, isDanger }) => {
  const IconComponent = icon;
  return (
    <div className="bg-white/[0.02] p-10 rounded-[40px] border border-white/5 space-y-5 hover:bg-white/[0.04] transition-all duration-500">
      <div className="flex items-center space-x-4 text-white/20">
        <IconComponent className="w-6 h-6 stroke-[1.5px]" />
        <span className="text-[10px] font-black uppercase tracking-[0.4em] leading-none">{label}</span>
      </div>
      <div className="space-y-1">
        <p className={`text-xl font-bold truncate tracking-tighter ${isDanger ? 'text-google-red' : 'text-white'}`}>{value}</p>
        <p className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em]">{sub || 'Validated Cluster'}</p>
      </div>
    </div>
  );
};

// --- Core Application ---

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [isBulk, setIsBulk] = useState(false);
  const [stats, setStats] = useState({ geo_distribution: [], total_scans: 0, malicious_scans: 0, risk_ratio: 0, avg_entropy: 0 });
  const [nodeSettings, setNodeSettings] = useState({});
  const [isAnalyticsOpen, setIsAnalyticsOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [summary, setSummary] = useState({ total: 0, threats: 0 });
  const [toast, setToast] = useState(null);
  const [savingSettings, setSavingSettings] = useState(false);

  const fetchHistory = async () => {
    try {
      const [{ data: h }, { data: s }] = await Promise.all([
        axios.get(`${API_BASE}/history?limit=50`),
        axios.get(`${API_BASE}/stats`)
      ]);
      setHistory(h.history || []);
      setStats(s || {});
      setSummary({ total: s.total_scans || 0, threats: s.malicious_scans || 0 });
    } catch { /* silent fail */ }
  };

  const fetchSettings = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/settings`);
      setNodeSettings(data);
    } catch { /* silent fail */ }
  };

  useEffect(() => {
    fetchHistory();
    const inv = setInterval(fetchHistory, 5000);
    return () => clearInterval(inv);
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!url) return;
    setLoading(true);
    try {
      showToast("Initializing Deep Core Scan...", "info");
      if (isBulk) {
        const urls = url.split('\n').map(u => u.trim()).filter(u => u);
        await axios.post(`${API_BASE}/scan/batch`, { urls });
        showToast("Batch logic analysis complete.", "success");
      } else {
        const { data } = await axios.post(`${API_BASE}/scan`, { url });
        setReport({ ...data.report, hash: data.hash });
        showToast(data.report.is_malicious ? "Critical violation flagged." : "Institutional clearance active.", data.report.is_malicious ? "danger" : "success");
      }
      fetchHistory(); setUrl("");
    } catch {
      showToast("System cluster communication error.", "danger");
    } finally { setLoading(false); }
  };

  const handleSaveSettings = async () => {
    setSavingSettings(true);
    try {
      await axios.post(`${API_BASE}/settings`, { settings: nodeSettings });
      showToast("Cluster config synchronized successfully.", "success");
      setIsSettingsOpen(false);
    } catch {
      showToast("Operational sync failure.", "danger");
    } finally {
      setSavingSettings(false);
    }
  };

  const showToast = (msg, type) => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#E8EAED] font-['Inter'] selection:bg-google-blue/30 selection:text-white">
      <div className="google-blur-bg" />

      {/* Modern Navigation */}
      <nav className="fixed top-0 left-0 w-full z-50 bg-black/60 backdrop-blur-2xl border-b border-white/5 px-12 h-26 flex items-center justify-between">
        <div className="flex items-center space-x-6 group cursor-default">
          <div className="bg-google-blue p-3 rounded-2xl shadow-[0_10px_30px_rgba(66,133,244,0.3)] border border-white/10 group-hover:scale-105 transition-transform duration-500">
            <Shield className="w-8 h-8 text-white stroke-[2.5px]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tighter uppercase leading-none">FinLink <span className="font-light text-white/30 lowercase italic ml-1">enterprise</span></h1>
            <p className="text-[10px] font-black text-white/20 tracking-[0.6em] mt-2 uppercase">L3 Cluster Node Active</p>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <button onClick={() => setIsAnalyticsOpen(true)} className="google-btn-outline flex items-center space-x-3 px-10 py-3.5 hover:bg-google-blue/10 hover:border-google-blue/30 transition-all">
            <BarChart3 className="w-5 h-5 text-google-blue" />
            <span className="leading-none mt-0.5">Cluster Stats</span>
          </button>
          <button onClick={() => { fetchSettings(); setIsSettingsOpen(true); }} className="p-4.5 hover:bg-white/10 rounded-full text-white/30 hover:text-white transition-all">
            <Settings className="w-7 h-7" />
          </button>
          <div className="w-px h-10 bg-white/5 mx-4" />
          <div className="flex items-center space-x-4 pl-2">
            <div className="text-right hidden sm:block">
              <p className="text-[10px] font-black text-white/20 uppercase tracking-widest">Operator</p>
              <p className="text-[12px] font-bold text-google-blue lowercase">admin.node.01</p>
            </div>
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-google-blue to-blue-600 border border-white/10 flex items-center justify-center text-[14px] font-black text-white shadow-xl">
              AD
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-10 pt-52 pb-40 space-y-32 animate-fade-in">

        {/* Inspection Command Center */}
        <section className="space-y-16">
          <div className="text-center space-y-6 max-w-4xl mx-auto">
            <div className="inline-flex items-center space-x-3 px-8 py-2.5 rounded-full bg-google-blue/10 border border-google-blue/20 text-google-blue text-[11px] font-black uppercase tracking-[0.4em] mb-4">
              <Zap className="w-4 h-4 fill-current" />
              <span>Primary Inspection Core</span>
            </div>
            <h2 className="text-5xl font-bold tracking-tighter text-white leading-tight">Investigate Asset Risks.</h2>
            <p className="text-white/20 text-2xl font-light leading-relaxed max-w-3xl mx-auto">Analyze network vectors, redirect logic, and visual artifacts with institutional precision.</p>
          </div>

          <div className="bg-[#171717]/80 backdrop-blur-3xl rounded-[56px] p-4 border border-white/5 shadow-[0_50px_100px_-30px_rgba(0,0,0,0.8)] focus-within:ring-[20px] focus-within:ring-google-blue/[0.04] transition-all duration-700">
            <form onSubmit={handleScan} className="flex flex-col md:flex-row items-stretch min-h-[120px]">
              <div className="pl-14 flex-1 flex items-center">
                {isBulk ? (
                  <textarea value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Node Cluster Scan (One URL Per Line)..." rows={4} className="w-full bg-transparent outline-none text-3xl font-light py-10 placeholder:text-white/5 resize-none custom-scrollbar leading-relaxed" />
                ) : (
                  <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Paste asset link for verification..." className="w-full bg-transparent outline-none text-3xl font-light py-10 placeholder:text-white/5" />
                )}
              </div>
              <div className="p-4 md:pr-4 flex items-center space-x-6">
                <button type="button" onClick={() => { setIsBulk(!isBulk); setUrl(""); }} className="text-xs font-black uppercase tracking-[0.3em] text-white/10 hover:text-google-blue transition-all px-10 h-[84px] rounded-[36px] hover:bg-white/[0.03] border border-transparent hover:border-white/5">
                  {isBulk ? 'Single' : 'Batch'}
                </button>
                <button type="submit" disabled={loading} className="google-btn-primary min-w-[280px] h-[84px] rounded-[36px] flex items-center justify-center space-x-4 shadow-[0_25px_60px_-10px_rgba(66,133,244,0.5)] active:scale-[0.95] group">
                  {loading ? <RefreshCw className="w-8 h-8 animate-spin text-white/40" /> : (
                    <>
                      <span className="text-base font-black tracking-[0.2em] uppercase">Investigate</span>
                      <ArrowRight className="w-6 h-6 group-hover:translate-x-2 transition-transform duration-500" />
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </section>

        {/* Global Telemetry Grid */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-12">
          <StatPill icon={Fingerprint} label="Global Dossier Count" value={summary.total.toLocaleString()} color="text-google-blue" />
          <StatPill icon={AlertIcon} label="Incursions Logged" value={summary.threats.toLocaleString()} color="text-google-red" />
          <StatPill icon={Network} label="Node Sync Latency" value="7.2ms" color="text-google-green" />
        </section>

        {/* Intelligence Archive */}
        <section className="space-y-12">
          <div className="flex items-center justify-between px-6">
            <div className="flex items-center space-x-5">
              <div className="w-1.5 h-1.5 rounded-full bg-google-blue shadow-[0_0_10px_#4285F4]" />
              <h3 className="text-[13px] font-black uppercase tracking-[0.5em] text-white/20 leading-none">Security Registry Log</h3>
            </div>
            <div className="text-[10px] font-black text-white/10 uppercase tracking-[0.3em] flex items-center space-x-4">
              <span>Data Persistence Active</span>
              <div className="w-px h-3 bg-white/5" />
              <span>Sync: 00:00:05</span>
            </div>
          </div>

          <GoogleCard className="shadow-2xl border-white/[0.03] bg-[#121212]">
            <div className="max-h-[800px] overflow-y-auto custom-scrollbar">
              {history.length > 0 ? (
                <div className="divide-y divide-white/[0.04]">
                  {history.map((log, i) => (
                    <HistoryRow key={i} item={log} onClick={() => setReport({ ...log.report, hash: log.hash })} />
                  ))}
                </div>
              ) : (
                <div className="p-48 text-center space-y-12 opacity-10 group">
                  <Database className="w-32 h-32 mx-auto stroke-[0.3px] transition-all group-hover:scale-110 group-hover:opacity-30 duration-1000" />
                  <p className="text-[11px] font-black tracking-[0.8em] uppercase">Persistent Vault Empty</p>
                </div>
              )}
            </div>
          </GoogleCard>
        </section>

      </main>

      {/* --- Overlay System --- */}

      {/* Dossier Insight Modal */}
      <Modal isOpen={!!report} onClose={() => setReport(null)} title="Security Asset Dossier">
        <div className="p-24 space-y-24">
          <div className="flex items-start justify-between">
            <div className="space-y-12 max-w-4xl">
              <div className={`inline-flex items-center space-x-5 px-10 py-3.5 rounded-[20px] text-[13px] font-black uppercase tracking-[0.4em] border transition-all ${report?.is_malicious ? 'bg-google-red/10 border-google-red/30 text-google-red shadow-[0_0_50px_rgba(234,67,53,0.15)]' : 'bg-google-green/10 border-google-green/30 text-google-green'}`}>
                {report?.is_malicious ? <AlertIcon className="w-7 h-7 animate-pulse" /> : <ShieldCheck className="w-7 h-7" />}
                <span>{report?.is_malicious ? 'Critical Security Violation' : 'Operational Clearance Active'}</span>
              </div>
              <h2 className="text-4xl font-bold tracking-tight break-all leading-[1.2] selection:bg-google-blue/40">{report?.url}</h2>
            </div>
            <div className="flex space-x-6 pt-2">
              {report?.hash && (
                <a href={`${API_BASE}/report/${report.hash}`} target="_blank" rel="noreferrer" className="p-10 bg-white/5 hover:bg-google-blue/10 rounded-[44px] border border-white/5 transition-all group shadow-2xl">
                  <FileText className="w-10 h-10 text-google-blue group-hover:scale-110 transition-transform duration-500" />
                </a>
              )}
              <button onClick={() => setReport(null)} className="p-10 bg-white/5 hover:bg-white/15 rounded-[44px] border border-white/5 text-white/10 hover:text-white transition-all shadow-2xl">
                <RefreshCw className="w-10 h-10" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-10">
            <DetailWidget icon={Globe2} label="Asset Origin" value={report?.geo?.country || 'Cloud Core'} sub={report?.geo?.isp?.split(' ')[0] || 'Resolving Provider'} />
            <DetailWidget icon={Lock} label="Auth Protocol" value={report?.ssl?.has_https ? 'TLS ACTIVE' : 'UNSECURED'} sub={report?.ssl?.issuer?.split(' ')[0] || 'Direct stream'} isDanger={!report?.ssl?.has_https} />
            <DetailWidget icon={Activity} label="Complexity Index" value={`${((report?.entropy || 0) / 8 * 100).toFixed(1)}%`} sub="Resource Entropy Meta" isDanger={report?.entropy > 4} />
            <DetailWidget icon={Clock} label="Route Nodes" value={`${report?.redirect_chain?.length || 1} Hops`} sub="Traversal Path Length" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
            <GoogleCard className="p-16 space-y-16 bg-white/[0.01] border-white/[0.03]">
              <div className="flex items-center justify-between border-b border-white/5 pb-12">
                <div className="flex items-center space-x-6 text-google-blue">
                  <Terminal className="w-10 h-10 stroke-[1px]" />
                  <h3 className="text-sm font-black uppercase tracking-[0.6em] leading-none mt-2">Machine Context</h3>
                </div>
              </div>
              <div className="space-y-12">
                {[
                  { l: "Registry IP", v: report?.geo?.ip || "0.0.0.0" },
                  { l: "Jurisdiction", v: report?.geo?.city || "Restricted Node" },
                  { l: "Host Header", v: report?.domain, m: true }
                ].map(r => (
                  <div key={r.l} className="flex justify-between items-end group border-b border-white/[0.02] pb-6">
                    <span className="text-white/20 font-black uppercase text-[11px] tracking-[0.25em] leading-none group-hover:text-white/40 transition-colors">{r.l}</span>
                    <span className={`text-white font-bold ${r.m ? 'font-mono text-[13px] opacity-20 select-all tracking-tighter' : 'text-2xl tracking-tighter'}`}>{r.v}</span>
                  </div>
                ))}
              </div>
            </GoogleCard>

            <div className="h-full">
              {report?.is_malicious ? (
                <div className="bg-google-red/[0.02] border border-google-red/10 rounded-[64px] p-16 h-full space-y-12 shadow-[inset_0_0_100px_rgba(234,67,53,0.08)]">
                  <div className="flex items-center space-x-6 text-google-red font-black uppercase tracking-[0.5em] text-xs">
                    <AlertTriangle className="w-10 h-10" />
                    <span>Security Violation Log</span>
                  </div>
                  <div className="space-y-6">
                    {report?.reasons.map((r, i) => (
                      <div key={i} className="bg-black/60 border border-white/5 p-10 rounded-[32px] text-base font-bold text-white/60 hover:text-white/90 transition-all cursor-default leading-relaxed shadow-xl">{r}</div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="bg-google-green/[0.02] border border-google-green/10 rounded-[64px] p-16 h-full flex flex-col items-center justify-center text-center space-y-12 group transition-all hover:bg-white/[0.04]">
                  <div className="relative">
                    <div className="absolute inset-0 bg-google-green/40 blur-[60px] rounded-full scale-[2] opacity-10" />
                    <ShieldCheck className="w-32 h-32 text-google-green/30 relative z-10 group-hover:scale-110 transition-transform duration-1000" />
                  </div>
                  <div className="space-y-6 max-w-sm">
                    <p className="text-lg font-black uppercase tracking-[0.5em] text-google-green leading-none">Integrity Pass</p>
                    <p className="text-xs font-bold text-white/10 uppercase tracking-[0.3em] leading-loose">No anomalous security vectors synchronized within current logic cycle.</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {report?.screenshot_path && (
            <div className="space-y-16 pt-12">
              <div className="flex items-center space-x-6 text-white/10 px-8">
                <Maximize2 className="w-8 h-8" />
                <h3 className="text-sm font-black uppercase tracking-[0.8em]">Visual Artifact Capture</h3>
              </div>
              <GoogleCard className="p-5 bg-black border-white/5 shadow-2xl">
                <img src={`${API_BASE}/screenshot/${report.screenshot_path.split('\\').pop()}`} alt="Evidence" className="w-full h-auto rounded-[40px] contrast-[1.1] grayscale-[0.3] hover:grayscale-0 transition-all duration-1000 blur-0 hover:shadow-[0_0_80px_rgba(66,133,244,0.1)]" />
              </GoogleCard>
            </div>
          )}
        </div>
      </Modal>

      {/* Telemetry Dashboard Modal */}
      <Modal isOpen={isAnalyticsOpen} onClose={() => setIsAnalyticsOpen(false)} title="Operational Telemetry">
        <div className="p-24 space-y-24 h-full">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-16 h-full items-center">
            <GoogleCard className="p-16 bg-white/[0.01] flex flex-col h-[700px] border-white/[0.03] shadow-[0_40px_100px_-20px_rgba(0,0,0,0.5)]">
              <div className="flex items-center justify-between border-b border-white/5 pb-10">
                <h3 className="text-[12px] font-black uppercase tracking-[0.5em] text-google-blue flex items-center space-x-4">
                  <Globe2 className="w-6 h-6 leading-none" />
                  <span>Cluster Origin Density</span>
                </h3>
              </div>
              <div className="flex-1 mt-10">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={stats.geo_distribution} innerRadius={120} outerRadius={180} paddingAngle={8} dataKey="value">
                      {stats.geo_distribution?.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={['#4285F4', '#34A853', '#EA4335', '#FBBC05', '#5F6368'][index % 5]} />
                      ))}
                    </Pie>
                    <ChartTooltip contentStyle={{ backgroundColor: '#121212', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '32px', padding: '24px', boxShadow: '0 20px 40px rgba(0,0,0,0.5)' }} itemStyle={{ fontWeight: 'black', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.1em' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </GoogleCard>

            <div className="flex flex-col justify-center space-y-12 h-full">
              {[
                { l: "Critical Incursion Flux", v: (stats.risk_ratio?.toFixed(1) || "0.0") + "%", c: "text-google-red", bg: "hover:bg-google-red/5" },
                { l: "Global Entropy Baseline", v: stats.avg_entropy?.toFixed(2) || "0.00", c: "text-white", bg: "hover:bg-white/[0.03]" }
              ].map(s => (
                <div key={s.l} className={`p-20 bg-white/[0.01] rounded-[72px] border border-white/5 space-y-8 group transition-all duration-700 shadow-2xl h-[330px] flex flex-col justify-center ${s.bg}`}>
                  <p className="text-[12px] font-black text-white/20 uppercase tracking-[0.6em] group-hover:translate-x-2 transition-transform">{s.l}</p>
                  <p className={`text-9xl font-black tracking-tighter leading-none ${s.c}`}>{s.v}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      {/* Config Interface Modal */}
      <Modal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} title="Logic Node Configuration">
        <div className="p-24 space-y-24">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-16">
            {[
              { k: "min_domain_age_days", l: "Clearance Window", d: "Operational maturity required for implicit clearance.", t: "number", u: "days" },
              { k: "max_entropy_threshold", l: "Complexity Sens", d: "Bit-level variability threshold for obfuscation triggers.", t: "number", u: "score" },
              { k: "jurisdiction_jump_limit", l: "Legal Perimeter", d: "Maximum cross-country routing hops authorized.", t: "number", u: "hops" }
            ].map(f => (
              <div key={f.k} className="space-y-8 group">
                <div className="flex justify-between items-end px-2">
                  <label className="text-[12px] font-black uppercase tracking-[0.5em] text-white/30 group-focus-within:text-google-blue transition-colors leading-none">{f.l}</label>
                  <span className="text-[10px] font-black text-white/10 uppercase tracking-widest">{f.u}</span>
                </div>
                <input type={f.t} value={nodeSettings[f.k] || ""} onChange={(e) => setNodeSettings({ ...nodeSettings, [f.k]: e.target.value })} className="w-full bg-[#1e1e1e] border border-white/[0.03] rounded-[40px] px-12 py-12 text-4xl font-light outline-none focus:ring-[24px] focus:ring-google-blue/[0.03] focus:border-google-blue/30 focus:bg-[#252525] transition-all" />
                <p className="text-[11px] font-bold text-white/10 uppercase tracking-widest pl-4 italic">{f.d}</p>
              </div>
            ))}
            <div className="flex flex-col justify-center space-y-8">
              <label className="text-[12px] font-black uppercase tracking-[0.5em] text-white/30 block leading-none px-2 text-center">Neural Logic Module</label>
              <button onClick={() => setNodeSettings({ ...nodeSettings, enable_vision_ai: nodeSettings.enable_vision_ai === "1" ? "0" : "1" })} className={`w-full p-14 rounded-[56px] border-[1.5px] flex items-center justify-between transition-all group duration-700 ${nodeSettings.enable_vision_ai === "1" ? 'bg-google-green/[0.04] border-google-green/30 text-google-green shadow-[0_40px_80px_-10px_rgba(52,168,83,0.15)]' : 'bg-white/[0.01] border-white/5 text-white/15 hover:border-white/20'}`}>
                <div className="flex items-center space-x-8">
                  <ShieldCheck className={`w-14 h-14 transition-all duration-700 ${nodeSettings.enable_vision_ai === "1" ? 'opacity-100' : 'opacity-20 translate-x-2'}`} />
                  <div className="text-left space-y-2">
                    <span className="text-lg font-black uppercase tracking-[0.4em] block">Vision Core</span>
                    <span className="text-[10px] font-bold opacity-30 uppercase tracking-widest">{nodeSettings.enable_vision_ai === "1" ? 'Fully Synchronized' : 'Offline Mode'}</span>
                  </div>
                </div>
                <div className={`w-10 h-10 rounded-full border-4 transition-all duration-700 ${nodeSettings.enable_vision_ai === "1" ? 'bg-google-green border-white/10 scale-110' : 'bg-transparent border-white/5'}`} />
              </button>
            </div>
          </div>
          <div className="pt-20 border-t border-white/5 flex flex-col items-center space-y-8">
            <button onClick={handleSaveSettings} disabled={savingSettings} className="google-btn-primary min-w-[500px] h-[100px] rounded-[44px] flex items-center justify-center space-x-8 shadow-[0_40px_100px_-20px_rgba(66,133,244,0.6)] active:scale-[0.98] transition-all group relative overflow-hidden">
              <div className="absolute inset-0 bg-white/10 translate-y-full group-hover:translate-y-0 transition-transform duration-500" />
              <Save className="w-8 h-8 relative z-10" />
              <span className="text-xl font-black tracking-[0.4em] uppercase relative z-10">{savingSettings ? 'Synchronizing Node...' : 'Commit Protocol'}</span>
            </button>
            <p className="text-[10px] font-black text-white/10 uppercase tracking-[0.5em]">Auth Level: Terminal Superuser</p>
          </div>
        </div>
      </Modal>

      {/* Persistence Notification Cluster */}
      <AnimatePresence>
        {toast && (
          <motion.div initial={{ opacity: 0, y: 100, scale: 0.8 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, scale: 0.7 }} className={`fixed bottom-20 left-1/2 -translate-x-1/2 z-[200] px-16 py-8 rounded-[48px] border flex items-center space-x-10 shadow-[0_60px_150px_-30px_rgba(0,0,0,1)] backdrop-blur-[60px] ${toast.type === 'danger' ? 'bg-google-red/90 border-white/20' : toast.type === 'success' ? 'bg-google-green/90 border-white/20' : 'bg-google-blue/90 border-white/20'}`}>
            {/* Using motion explicitly here */}
            <div className="w-14 h-14 bg-white/20 rounded-3xl flex items-center justify-center shadow-inner">
              {toast.type === 'danger' ? <AlertIcon className="w-8 h-8 text-white" /> : <ShieldCheck className="w-8 h-8 text-white" />}
            </div>
            <div className="space-y-1">
              <p className="text-[11px] font-black text-white/30 uppercase tracking-[0.6em] leading-none mb-2">Cluster Event</p>
              <span className="text-xl font-black tracking-[0.2em] uppercase text-white leading-none whitespace-nowrap">{toast.msg}</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <footer className="max-w-6xl mx-auto px-12 py-32 border-t border-white/5 flex flex-col md:flex-row items-center justify-between opacity-10 text-[10px] font-black uppercase tracking-[0.8em] space-y-16 md:space-y-0 text-center md:text-left">
        <div className="space-y-4">
          <div className="flex items-center justify-center md:justify-start space-x-6 text-google-blue">
            <Network className="w-6 h-6" />
            <p className="mt-1">FinLink Protocol Stack</p>
          </div>
          <p className="opacity-40">System Node: Cluster-Alpha-7 • Verified by Antigravity AI Engine</p>
        </div>
        <div className="flex flex-wrap justify-center gap-16">
          <a href="#" className="hover:text-google-blue transition-colors">Safety Logic</a>
          <a href="#" className="hover:text-google-blue transition-colors">Risk Meta</a>
          <a href="#" className="text-google-blue hover:text-white transition-colors border-b border-google-blue/20 pb-1">Registry Core</a>
        </div>
      </footer>
    </div>
  );
}

export default App;

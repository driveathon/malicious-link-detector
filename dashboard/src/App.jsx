import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, AlertTriangle, CheckCircle, Search, Clock, ChevronRight, Activity, Globe, Lock, ExternalLink, Image as ImageIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE = "http://localhost:8000";

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const resp = await axios.get(`${API_BASE}/history`);
      setHistory(resp.data.history || []);
    } catch (err) {
      console.error("Failed to fetch history", err);
    }
  };

  const scanUrl = async (e) => {
    if (e) e.preventDefault();
    if (!url) return;

    setLoading(true);
    setReport(null);
    setError(null);

    try {
      const resp = await axios.post(`${API_BASE}/scan`, { url });
      setReport(resp.data.report);
      fetchHistory(); // Refresh history
    } catch (err) {
      setError("Failed to scan URL. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen p-6 md:p-12 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <header className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="bg-primary/20 p-2 rounded-lg">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Malicious Link Detector</h1>
            <p className="text-gray-400 text-sm">Advanced heuristic & visual analysis</p>
          </div>
        </div>
        <div className="hidden md:flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs text-gray-500 bg-white/5 py-1 px-3 rounded-full">
            <Activity className="w-3 h-3 text-success animate-pulse" />
            <span>Backend Online</span>
          </div>
        </div>
      </header>

      {/* Main Search */}
      <section className="glass p-8 space-y-6">
        <form onSubmit={scanUrl} className="relative group">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500 group-focus-within:text-primary transition-colors" />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste a suspicious link to scan (e.g. http://my-bank.com.scam)..."
            className="w-full bg-white/5 border border-white/10 rounded-xl py-4 pl-12 pr-32 outline-none focus:border-primary/50 focus:ring-4 focus:ring-primary/10 transition-all text-lg"
          />
          <button
            type="submit"
            disabled={loading}
            className="absolute right-2 top-1/2 -translate-y-1/2 bg-primary hover:bg-primary/80 text-white px-6 py-2 rounded-lg font-medium transition-all disabled:opacity-50"
          >
            {loading ? "Scanning..." : "Analyze"}
          </button>
        </form>

        {error && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-danger flex items-center space-x-2 text-sm">
            <AlertTriangle className="w-4 h-4" />
            <span>{error}</span>
          </motion.div>
        )}
      </section>

      <main className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Report */}
        <div className="lg:col-span-2 space-y-8">
          <AnimatePresence mode="wait">
            {report ? (
              <motion.div
                key="report"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className={`glass p-8 space-y-8 border-l-4 ${report.is_malicious ? 'border-l-danger bg-danger/5 glow-danger' : 'border-l-success bg-success/5'}`}
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      {report.is_malicious ? <AlertTriangle className="w-6 h-6 text-danger" /> : <CheckCircle className="w-6 h-6 text-success" />}
                      <h2 className="text-2xl font-bold">{report.is_malicious ? "Found Threats" : "Link is Safe"}</h2>
                    </div>
                    <p className="text-gray-400 break-all">{report.url}</p>
                  </div>
                  <div className={`px-4 py-1 rounded-full text-xs font-bold uppercase ${report.is_malicious ? 'bg-danger/20 text-danger' : 'bg-success/20 text-success'}`}>
                    {report.is_malicious ? "Suspicious" : "Clean"}
                  </div>
                </div>

                {report.is_malicious && report.reasons.length > 0 && (
                  <div className="grid gap-4">
                    <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">Detections</h3>
                    <div className="grid sm:grid-cols-2 gap-3">
                      {report.reasons.map((reason, i) => (
                        <div key={i} className="flex items-start space-x-2 bg-white/5 p-3 rounded-lg border border-white/5">
                          <AlertTriangle className="w-4 h-4 text-warning mt-0.5 shrink-0" />
                          <span className="text-sm text-gray-300">{reason}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Analysis Details */}
                <div className="grid sm:grid-cols-3 gap-4">
                  <div className="bg-white/5 p-4 rounded-xl space-y-2 border border-white/5">
                    <div className="flex items-center space-x-2 text-primary">
                      <Globe className="w-4 h-4" />
                      <span className="text-xs font-semibold uppercase">Domain Info</span>
                    </div>
                    <p className="text-lg font-bold truncate">{report.domain}</p>
                    {report.whois && (
                      <p className="text-xs text-gray-500">Created: {report.whois.age_days} days ago</p>
                    )}
                  </div>
                  <div className="bg-white/5 p-4 rounded-xl space-y-2 border border-white/5">
                    <div className="flex items-center space-x-2 text-primary">
                      <Lock className="w-4 h-4" />
                      <span className="text-xs font-semibold uppercase">SSL Status</span>
                    </div>
                    {report.ssl ? (
                      <>
                        <p className={`text-lg font-bold ${report.ssl.has_https ? 'text-success' : 'text-danger'}`}>
                          {report.ssl.has_https ? "Secure" : "Insecure"}
                        </p>
                        <p className="text-xs text-gray-500">{report.ssl.issuer || "No Issuer"}</p>
                      </>
                    ) : <p className="text-gray-500">N/A</p>}
                  </div>
                  <div className="bg-white/5 p-4 rounded-xl space-y-2 border border-white/5">
                    <div className="flex items-center space-x-2 text-primary">
                      <ExternalLink className="w-4 h-4" />
                      <span className="text-xs font-semibold uppercase">Redirects</span>
                    </div>
                    <p className="text-lg font-bold">{report.redirect_chain?.length || 1}</p>
                    <p className="text-xs text-gray-500 truncate">{report.final_url !== report.url ? "Traced to dest" : "Direct Link"}</p>
                  </div>
                </div>

                {/* Screenshot Section (Conditional) */}
                {report.screenshot_path && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">Visual Evidence</h3>
                      <div className="flex items-center space-x-2 text-xs text-primary">
                        <ImageIcon className="w-3 h-3" />
                        <span>Playwright Capture</span>
                      </div>
                    </div>
                    <div className="rounded-xl overflow-hidden border border-white/10 ring-4 ring-black/20 group relative cursor-zoom-in">
                      <img
                        src={`${API_BASE}/screenshot/${report.screenshot_path.split('\\').pop()}`}
                        alt="URL Screenshot"
                        className="w-full h-auto max-h-[400px] object-cover group-hover:scale-105 transition-transform duration-500"
                      />
                    </div>
                  </div>
                )}
              </motion.div>
            ) : !loading && (
              <div className="h-full flex flex-col items-center justify-center space-y-4 text-gray-600 opacity-20 py-20 border-2 border-dashed border-white/10 rounded-2xl">
                <Shield className="w-20 h-20" />
                <p className="text-xl font-medium tracking-tight uppercase">Waiting for analysis</p>
              </div>
            )}

            {loading && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full flex flex-col items-center justify-center space-y-6 py-20">
                <div className="relative">
                  <div className="w-16 h-16 border-4 border-primary/20 rounded-full"></div>
                  <div className="w-16 h-16 border-4 border-t-primary rounded-full animate-spin absolute top-0"></div>
                </div>
                <div className="text-center space-y-2">
                  <p className="text-xl font-medium">Analyzing URL...</p>
                  <p className="text-sm text-gray-500">Tracing redirects and checking heuristics</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right Column: History */}
        <aside className="space-y-6">
          <div className="flex items-center space-x-2 px-1">
            <Clock className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold tracking-widest uppercase text-gray-500">Recent Scans</h2>
          </div>
          <div className="grid gap-3">
            {history.length > 0 ? history.map((item, i) => (
              <button
                key={i}
                onClick={() => {
                  setReport(item.report);
                  setUrl(item.url);
                }}
                className="glass p-4 flex items-center space-x-4 hover:bg-white/10 transition-all text-left w-full group"
              >
                <div className={`w-2 h-2 rounded-full shrink-0 ${item.report.is_malicious ? 'bg-danger shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'bg-success shadow-[0_0_8px_rgba(34,197,94,0.5)]'}`}></div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate group-hover:text-primary transition-colors">{item.url}</p>
                  <p className="text-xs text-gray-500">{new Date(item.timestamp).toLocaleString()}</p>
                </div>
                <ChevronRight className="w-4 h-4 text-gray-700 mt-1" />
              </button>
            )) : (
              <p className="text-sm text-gray-500 px-1 italic">No recent scans found.</p>
            )}
          </div>
        </aside>
      </main>

      {/* Footer */}
      <footer className="pt-12 pb-6 border-t border-white/5 flex justify-between items-center text-xs text-gray-600">
        <p>© 2026 Antigravity Security Systems</p>
        <div className="flex items-center space-x-4">
          <button className="hover:text-primary transition-colors">API Docs</button>
          <button className="hover:text-primary transition-colors">Source Code</button>
        </div>
      </footer>
    </div>
  );
}

export default App;

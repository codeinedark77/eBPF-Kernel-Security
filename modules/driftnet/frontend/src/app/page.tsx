"use client";

import { useEffect, useState, useRef } from "react";

const API_BASE: string = ""; // For local dev it would be http://localhost:8080, but Next.js will be served by Go so "" is correct
const THRESHOLD = 0.5;
const POLL_MS = 2000;

export default function Dashboard() {
  const [recent, setRecent] = useState<any[]>([]);
  const [flagged, setFlagged] = useState<any[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [activeSource, setActiveSource] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [expandedAttr, setExpandedAttr] = useState<Set<number>>(new Set());

  useEffect(() => {
    let isMounted = true;
    let ws: WebSocket;

    const fetchInitial = async () => {
      try {
        const [recentRes, flaggedRes, sourcesRes] = await Promise.all([
          fetch(`${API_BASE}/api/events/recent`),
          fetch(`${API_BASE}/api/events/flagged`),
          fetch(`${API_BASE}/api/sources`),
        ]);
        if (!recentRes.ok || !flaggedRes.ok || !sourcesRes.ok) throw new Error("bad response");
        
        const recentData = await recentRes.json() || [];
        const flaggedData = await flaggedRes.json() || [];
        const sourcesData = await sourcesRes.json();
        
        if (!isMounted) return;
        
        setRecent(recentData);
        setFlagged(flaggedData);
        setSources((sourcesData.sources || []).sort());
        setConnected(true);
        
        setActiveSource((prev) => {
          if (!prev && sourcesData.sources && sourcesData.sources.length > 0) {
            return sourcesData.sources[0];
          }
          return prev;
        });

        // Initialize WebSocket for real-time telemetry
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = API_BASE ? API_BASE.replace(/^https?:\/\//, '') : window.location.host;
        ws = new WebSocket(`${protocol}//${host}/ws/events`);
        
        ws.onopen = () => { if (isMounted) setConnected(true); };
        ws.onclose = () => { if (isMounted) setConnected(false); };
        ws.onmessage = (msg) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(msg.data);
            if (data.type === 'new_event') {
              const ev = data.event;
              setRecent((prev) => [ev, ...prev].slice(0, 500));
              
              const sourceKey = `${ev.device}:${ev.app}`;
              setSources((prev) => {
                if (!prev.includes(sourceKey)) return [...prev, sourceKey].sort();
                return prev;
              });

              if (ev.ncd_score >= THRESHOLD || (ev.rule_matches && ev.rule_matches.length > 0)) {
                setFlagged((prev) => [ev, ...prev]);
              }
            } else if (data.type === 'triage_update') {
              setRecent((prev) => prev.map(e => e.seq === data.seq ? { ...e, triage: data.triage } : e));
              setFlagged((prev) => prev.map(e => e.seq === data.seq ? { ...e, triage: data.triage } : e));
            }
          } catch (e) {
            console.error("ws parse error", e);
          }
        };

      } catch (e) {
        if (isMounted) setConnected(false);
      }
    };

    fetchInitial();
    // Fallback polling for robustness if WS dies
    const interval = setInterval(fetchInitial, POLL_MS * 5);
    
    return () => {
      isMounted = false;
      clearInterval(interval);
      if (ws) ws.close();
    };
  }, []);

  const currentSourceEvents = () => {
    if (!activeSource) return [];
    return recent.filter((ev) => `${ev.device}:${ev.app}` === activeSource);
  };

  const toggleAttr = (seq: number) => {
    setExpandedAttr((prev) => {
      const next = new Set(prev);
      if (next.has(seq)) next.delete(seq);
      else next.add(seq);
      return next;
    });
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[var(--color-bg-base)]">
      <div className="mesh-bg"></div>
      {/* Topbar */}
      <header className="flex items-center gap-3 px-6 py-4 border-b border-[var(--color-border)] glass shrink-0 z-20">
        <div className={`w-2.5 h-2.5 rounded-full transition-all duration-300 ${connected ? 'bg-[var(--color-brand-cyan)] animate-pulse-cyan' : 'bg-[var(--color-brand-crimson)] shadow-[0_0_8px_var(--color-brand-crimson)]'}`} />
        <div className="font-mono font-bold text-[18px] tracking-[0.08em] text-[var(--color-text-main)] uppercase drop-shadow-md">
          drift<span className="text-[var(--color-brand-cyan)] cyber-glow px-1.5 py-0.5 rounded ml-1 bg-black/40">net</span>
        </div>
        <div className="ml-auto flex gap-6 font-mono text-[13px] text-[var(--color-text-muted)] tracking-widest font-bold">
          {connected ? (
            <span className="text-[var(--color-brand-cyan)] flex items-center gap-2 neon-cyan">
              <span className="w-2 h-2 rounded-full bg-[var(--color-brand-cyan)] animate-pulse"></span>
              LIVE TELEMETRY
            </span>
          ) : (
            <span className="text-[var(--color-brand-crimson)] neon-crimson">DISCONNECTED FROM DRIFTNETD</span>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 min-h-0 p-4 gap-4">
        {/* Sidebar */}
        <aside className="w-[260px] shrink-0 border border-[var(--color-border)] rounded-lg glass overflow-hidden flex flex-col z-10 shadow-2xl">
          <div className="font-mono text-[11px] tracking-[0.15em] text-[var(--color-text-muted2)] uppercase px-5 py-4 border-b border-[var(--color-border)] bg-black/20">Active Targets</div>
          <div className="overflow-y-auto flex-1 p-2">
            {!sources.length ? (
              <div className="px-3 py-4 text-[13px] text-[var(--color-text-muted)] leading-relaxed italic">
                Awaiting kernel telemetry...
              </div>
            ) : (
              sources.map((key) => {
                const idx = key.indexOf(":");
                const device = idx === -1 ? key : key.substring(0, idx);
                const app = idx === -1 ? "" : key.substring(idx + 1);
                const isActive = key === activeSource;
                
                return (
                  <div 
                    key={key}
                    onClick={() => setActiveSource(key)}
                    className={`flex flex-col gap-1 py-3 px-3 mb-1 rounded-md cursor-pointer font-mono transition-all duration-300
                      ${isActive ? 'bg-[var(--color-brand-cyan-dim)] border border-[var(--color-brand-cyan)] shadow-[inset_0_0_12px_rgba(0,243,255,0.2)]' : 'border border-transparent hover:bg-white/5 hover:border-white/10'}`}
                  >
                    <div className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wider">{device}</div>
                    <div className={`text-[13px] font-bold tracking-wide truncate ${isActive ? 'text-white neon-cyan' : 'text-[var(--color-text-main)]'}`}>{app}</div>
                  </div>
                );
              })
            )}
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col min-w-0 gap-4">
          <KpiGrid total={recent.length} flagged={flagged.length} sources={sources.length} />
          
          <div className="flex-1 flex flex-col min-w-0 glass border border-[var(--color-border)] rounded-lg shadow-2xl overflow-hidden relative">
            <ScopePanel activeSource={activeSource} events={currentSourceEvents()} />
            <LogPanel events={currentSourceEvents()} activeSource={activeSource} />
          </div>
        </main>
      </div>

      {/* Drawer */}
      <div className={`shrink-0 glass border-t border-[var(--color-border)] flex flex-col transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] shadow-[0_-10px_40px_rgba(0,0,0,0.8)] ${drawerOpen ? 'h-[40vh]' : 'h-[44px]'}`}>
        <div 
          className="flex items-center gap-3 px-6 py-3 cursor-pointer font-mono text-[12px] tracking-[0.1em] text-[var(--color-brand-crimson)] font-bold uppercase shrink-0 hover:bg-white/5 transition-colors"
          onClick={() => setDrawerOpen(!drawerOpen)}
        >
          <span className={`transition-transform duration-300 ${drawerOpen ? 'rotate-180' : ''}`}>▲</span> 
          Threat Intel: Flagged Events
          <span className="bg-[var(--color-brand-crimson)] text-black font-bold rounded px-2 py-0.5 text-[11px] ml-1 shadow-[0_0_12px_var(--color-brand-crimson)]">{flagged.length}</span>
        </div>
        <div className="overflow-y-auto px-6 pb-4">
          {!flagged.length ? (
            <div className="py-4 text-[var(--color-text-muted)] font-mono text-[13px] italic">Zero critical anomalies detected across infrastructure.</div>
          ) : (
            [...flagged].sort((a, b) => b.seq - a.seq).map((ev) => (
              <FlaggedRow key={ev.seq} ev={ev} expanded={expandedAttr.has(ev.seq)} onToggle={() => toggleAttr(ev.seq)} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// KpiGrid Component
// ----------------------------------------------------------------------
function KpiGrid({ total, flagged, sources }: { total: number, flagged: number, sources: number }) {
  return (
    <div className="grid grid-cols-3 gap-4 shrink-0">
      <div className="glass border border-[var(--color-border)] rounded-lg p-5 flex flex-col justify-between relative overflow-hidden group hover:border-[var(--color-brand-cyan)] transition-colors">
        <div className="absolute top-0 right-0 w-32 h-32 bg-[var(--color-brand-cyan)]/10 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-[var(--color-brand-cyan)]/20 transition-all duration-500"></div>
        <div className="font-mono text-[11px] font-bold tracking-[0.2em] text-[var(--color-brand-cyan)] uppercase mb-2">Total Syscalls</div>
        <div className="font-mono text-4xl text-white font-light neon-cyan">{total.toLocaleString()}</div>
      </div>
      <div className="glass border border-[var(--color-brand-crimson)]/50 rounded-lg p-5 flex flex-col justify-between relative overflow-hidden group hover:border-[var(--color-brand-crimson)] transition-colors">
        <div className="absolute top-0 right-0 w-32 h-32 bg-[var(--color-brand-crimson)]/20 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-[var(--color-brand-crimson)]/30 transition-all duration-500"></div>
        <div className="font-mono text-[11px] font-bold tracking-[0.2em] text-[var(--color-brand-crimson)] uppercase mb-2">Active Anomalies</div>
        <div className="font-mono text-4xl text-[var(--color-brand-crimson)] font-bold neon-crimson">{flagged.toLocaleString()}</div>
      </div>
      <div className="glass border border-[var(--color-border)] rounded-lg p-5 flex flex-col justify-between relative overflow-hidden group hover:border-[var(--color-brand-violet)] transition-colors">
        <div className="absolute top-0 right-0 w-32 h-32 bg-[var(--color-brand-violet)]/10 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-[var(--color-brand-violet)]/20 transition-all duration-500"></div>
        <div className="font-mono text-[11px] font-bold tracking-[0.2em] text-[var(--color-brand-violet)] uppercase mb-2">Monitored Targets</div>
        <div className="font-mono text-4xl text-white font-light" style={{textShadow: '0 0 10px rgba(181,60,255,0.7)'}}>{sources}</div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// ScopePanel Component
// ----------------------------------------------------------------------
function ScopePanel({ activeSource, events }: { activeSource: string | null, events: any[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width || canvas.parentElement!.clientWidth;
    const h = 160;
    
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.height = h + 'px';
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    let animationFrame: number;
    let scanPos = 0;

    const render = () => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      // Draw background grid
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
      ctx.lineWidth = 1;
      for (let i = 0; i < w; i += 40) {
        ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, h); ctx.stroke();
      }
      for (let i = 0; i < h; i += 40) {
        ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(w, i); ctx.stroke();
      }

      if (events.length > 0) {
        const ordered = [...events].sort((a, b) => a.seq - b.seq);
        const n = ordered.length;
        const barGap = 3;
        const barW = Math.max(2, Math.min(12, w / n - barGap));
        const usableW = n * (barW + barGap);
        const startX = Math.max(0, w - usableW);

        // Threshold line
        const thresholdY = h - THRESHOLD * (h - 20) - 10;
        ctx.strokeStyle = 'rgba(255, 0, 60, 0.5)';
        ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(0, thresholdY); ctx.lineTo(w, thresholdY); ctx.stroke();
        ctx.setLineDash([]);
        
        ctx.fillStyle = 'rgba(255, 0, 60, 0.8)';
        ctx.font = 'bold 10px monospace';
        ctx.fillText('CRIT_THRESH', 10, thresholdY - 5);

        // Draw Bars
        ordered.forEach((ev, i) => {
          const x = startX + i * (barW + barGap);
          const score = Math.max(0, Math.min(1, ev.ncd_score || 0));
          const barH = score * (h - 20);
          const y = h - barH - 10;
          
          const isFlagged = score >= THRESHOLD;
          
          // Create gradient for bars
          const grad = ctx.createLinearGradient(0, y, 0, h);
          if (isFlagged) {
            grad.addColorStop(0, '#ff003c');
            grad.addColorStop(1, 'rgba(255, 0, 60, 0.1)');
          } else {
            grad.addColorStop(0, '#00f3ff');
            grad.addColorStop(1, 'rgba(0, 243, 255, 0.1)');
          }
          
          ctx.fillStyle = grad;
          ctx.fillRect(x, y, barW, barH);
        });
      }

      // Animated Radar Scan Line
      scanPos = (scanPos + 2) % w;
      
      const scanGrad = ctx.createLinearGradient(scanPos - 100, 0, scanPos, 0);
      scanGrad.addColorStop(0, 'rgba(0, 243, 255, 0)');
      scanGrad.addColorStop(1, 'rgba(0, 243, 255, 0.2)');
      
      ctx.fillStyle = scanGrad;
      ctx.fillRect(scanPos - 100, 0, 100, h);
      
      ctx.fillStyle = 'rgba(0, 243, 255, 0.9)';
      ctx.shadowColor = 'rgba(0, 243, 255, 0.8)';
      ctx.shadowBlur = 10;
      ctx.fillRect(scanPos, 0, 2, h);
      ctx.shadowBlur = 0;

      animationFrame = requestAnimationFrame(render);
    };

    render();
    
    return () => cancelAnimationFrame(animationFrame);
  }, [events]);

  const idx = activeSource ? activeSource.indexOf(':') : -1;
  const device = idx === -1 ? activeSource : activeSource?.substring(0, idx);
  const app = idx === -1 ? "" : activeSource?.substring(idx + 1);

  return (
    <div className="border-b border-[var(--color-border)] bg-black/40 shrink-0">
      <div className="px-6 py-4 flex items-baseline justify-between">
        <div className="flex items-baseline gap-3">
          <div className="font-mono text-[14px] font-bold text-white tracking-wide">{activeSource ? `${device} / ${app}` : 'AWAITING TARGET SELECTION'}</div>
          <div className="text-[12px] text-[var(--color-text-muted)] font-mono">
            {activeSource ? `[${events.length} EVENTS IN RING BUFFER]` : ''}
          </div>
        </div>
      </div>
      <div className="px-6 pb-4">
        <canvas ref={canvasRef} className="block w-full h-[160px] rounded-lg bg-[#080a0f] border border-[#1e2430] shadow-[inset_0_0_30px_rgba(0,0,0,0.8)]" />
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// LogPanel Component
// ----------------------------------------------------------------------
function LogPanel({ events, activeSource }: { events: any[], activeSource: string | null }) {
  const displayEvents = [...events].sort((a, b) => b.seq - a.seq).slice(0, 200);

  if (!displayEvents.length) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-center p-10 text-[var(--color-text-muted)]">
        <div className="font-mono text-[14px] text-[var(--color-text-main)] mb-2">
          {activeSource ? 'Telemetry buffer empty for this target.' : 'Standby for telemetry...'}
        </div>
        <div className="text-[13px] max-w-[400px] leading-relaxed">
          The eBPF probes are active. Once execution, network, or file-system syscalls are intercepted in Ring-0, they will stream here in real-time.
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto px-6 pb-6">
      <table className="w-full border-collapse font-mono text-[12.5px]">
        <thead className="sticky top-0 bg-[var(--color-panel-glass)] backdrop-blur-md z-10">
          <tr>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">SEQ</th>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">TIME</th>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">SYSCALL</th>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">NCD</th>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">RULES</th>
            <th className="text-left font-medium text-[var(--color-text-muted2)] uppercase tracking-wider px-3 py-3 border-b border-[var(--color-border)]">PAYLOAD</th>
          </tr>
        </thead>
        <tbody>
          {displayEvents.map((ev) => {
            const isFlagged = ev.ncd_score >= THRESHOLD || (ev.rule_matches && ev.rule_matches.length > 0);
            return (
              <tr key={ev.seq} className={`data-row ${isFlagged ? 'data-row-flagged border-white/10' : 'border-white/5'} border-b group`}>
              <td className="px-3 py-2.5 text-[var(--color-text-muted)]">{ev.seq}</td>
              <td className="px-3 py-2.5 text-[var(--color-text-muted)]">{fmtTime(ev.timestamp)}</td>
              <td className="px-3 py-2.5">
                <span className={`kind-tag kind-${ev.kind}`}>{ev.kind}</span>
              </td>
              <td className={`px-3 py-2.5 font-tabular-nums ${ev.ncd_score >= THRESHOLD ? 'text-[var(--color-brand-crimson)] font-bold text-[14px] neon-crimson' : 'text-white'}`}>
                {(ev.ncd_score ?? 0).toFixed(3)}
              </td>
              <td className="px-3 py-2.5">
                <RuleBadges matches={ev.rule_matches} />
              </td>
              <td className="px-3 py-2.5 text-[var(--color-text-muted)] max-w-[400px] truncate group-hover:text-white transition-colors">
                {summarizeDetail(ev.detail)}
              </td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ----------------------------------------------------------------------
// FlaggedRow Component
// ----------------------------------------------------------------------
function FlaggedRow({ ev, expanded, onToggle }: { ev: any, expanded: boolean, onToggle: () => void }) {
  return (
    <div className="py-3 border-b border-white/5 flex flex-col gap-2">
      <div className="flex items-center gap-3 font-mono text-[13px]">
        <span className="text-[var(--color-text-muted)]">#{ev.seq}</span>
        <span className="text-white font-bold tracking-wide">{ev.device}:{ev.app}</span>
        <span className={`kind-tag kind-${ev.kind}`}>{ev.kind}</span>
        <span className="font-tabular-nums text-[var(--color-brand-crimson)] font-bold neon-crimson">{(ev.ncd_score ?? 0).toFixed(3)}</span>
        <RuleBadges matches={ev.rule_matches} />
        <span className="text-[var(--color-text-muted)] tracking-widest">{fmtTime(ev.timestamp)}</span>
        <button 
          onClick={onToggle}
          className="ml-auto font-mono text-[11px] font-bold text-[var(--color-brand-cyan)] bg-transparent border border-[var(--color-brand-cyan)]/50 rounded px-3 py-1 cursor-pointer hover:bg-[var(--color-brand-cyan)] hover:text-black hover:shadow-[0_0_12px_var(--color-brand-cyan)] transition-all"
        >
          ANALYZE DELTA
        </button>
      </div>
      <div className={`text-[13px] tracking-wide leading-relaxed pl-1 ${ev.triage ? 'text-[var(--color-text-main)]' : 'text-[var(--color-text-muted)] italic'}`}>
        {ev.triage || 'AI Triage Pending...'}
      </div>
      {expanded && <AttrPanel attrs={ev.attribution} />}
    </div>
  );
}

function AttrPanel({ attrs }: { attrs: any[] }) {
  if (!attrs || !attrs.length) {
    return (
      <div className="mt-2 p-3 bg-black/40 border border-white/10 rounded text-[var(--color-text-muted)] italic font-mono text-[12px]">
        No field-level attribution for this anomaly (baseline creation).
      </div>
    );
  }

  const maxAbs = Math.max(...attrs.map(a => Math.abs(a.delta)), 0.001);

  return (
    <div className="mt-2 p-3 bg-black/60 border border-white/10 rounded font-mono text-[12px] shadow-inner">
      {attrs.map((a, i) => {
        const pct = Math.min(100, (Math.abs(a.delta) / maxAbs) * 100);
        return (
          <div key={i} className="flex items-center gap-3 py-1">
            <div className="w-[140px] shrink-0 text-white truncate">{a.field}</div>
            <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full ${a.delta < 0 ? 'bg-[var(--color-brand-cyan)] shadow-[0_0_8px_var(--color-brand-cyan)]' : 'bg-[var(--color-brand-crimson)] shadow-[0_0_8px_var(--color-brand-crimson)]'}`} 
                style={{ width: `${pct}%` }} 
              />
            </div>
            <div className="w-[60px] shrink-0 text-right text-white font-tabular-nums">
              {a.delta >= 0 ? '+' : ''}{a.delta.toFixed(3)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------
function fmtTime(ts: string) {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function summarizeDetail(detail: any) {
  try {
    const o = typeof detail === 'string' ? JSON.parse(detail) : detail;
    return Object.entries(o).map(([k, v]) => `${k}=${v}`).join(' · ');
  } catch (e) {
    return String(detail);
  }
}

function RuleBadges({ matches }: { matches: string[] }) {
  if (!matches || !matches.length) return null;
  return (
    <>
      {matches.map((r, i) => {
        if (r.startsWith('app_updated:')) {
          const [from, to] = r.slice('app_updated:'.length).split('->');
          return <span key={i} className="rule-badge rule-badge-info">UPDATED {from} &rarr; {to}</span>;
        }
        if (r.startsWith('compressor_disagreement:')) {
          const parts = r.slice('compressor_disagreement:'.length);
          return <span key={i} className="rule-badge rule-badge-ambiguous">DISAGREEMENT ({parts})</span>;
        }
        if (r.startsWith('secret_leak:')) {
          const pattern = r.slice('secret_leak:'.length);
          return <span key={i} className="rule-badge rule-badge-default">LEAK: {pattern}</span>;
        }
        if (r === 'insecure_intent') {
          return <span key={i} className="rule-badge rule-badge-vuln">⚠ INSECURE INTENT</span>;
        }
        if (r === 'insecure_sql_query') {
          return <span key={i} className="rule-badge rule-badge-vuln">⚠ SQL INJECTION</span>;
        }
        if (r === 'insecure_webview') {
          return <span key={i} className="rule-badge rule-badge-vuln">⚠ INSECURE WEBVIEW</span>;
        }
        if (r === 'weak_biometric') {
          return <span key={i} className="rule-badge rule-badge-vuln">⚠ WEAK BIOMETRIC</span>;
        }
        return <span key={i} className="rule-badge rule-badge-default">{r.toUpperCase()}</span>;
      })}
    </>
  );
}


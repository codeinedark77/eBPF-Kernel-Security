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
    <div className="flex flex-col h-screen overflow-hidden">
      {/* Topbar */}
      <header className="flex items-center gap-3 px-5 py-3 border-b border-[var(--color-border)] bg-[var(--color-panel)] shrink-0 z-10">
        <div className={`w-2 h-2 rounded-full transition-all duration-300 ${connected ? 'bg-[var(--color-brand-amber)] animate-pulse-amber' : 'bg-[var(--color-brand-red)] shadow-[0_0_8px_var(--color-brand-red)]'}`} />
        <div className="font-mono font-bold text-[15px] tracking-[0.02em] text-[var(--color-text-main)]">
          drift<span className="text-[var(--color-brand-cyber)] cyber-glow px-1 rounded ml-1">net</span>
        </div>
        <div className="ml-auto flex gap-[18px] font-mono text-[12px] text-[var(--color-text-muted)]">
          <span><b className="text-[var(--color-text-main)] font-semibold">{sources.length}</b> sources</span>
          <span><b className="text-[var(--color-text-main)] font-semibold">{recent.length}</b> events</span>
          <span><b className="text-[var(--color-text-main)] font-semibold">{flagged.length}</b> flagged</span>
          {connected ? (
            <span className="text-[var(--color-text-muted)]">connected to driftnetd</span>
          ) : (
            <span className="text-[var(--color-brand-red)]">cannot reach driftnetd — is it running?</span>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 min-h-0">
        {/* Sidebar */}
        <aside className="w-[240px] shrink-0 border-r border-[var(--color-border)] bg-[var(--color-panel)] overflow-y-auto py-3.5 z-0">
          <div className="font-mono text-[10px] tracking-[0.12em] text-[var(--color-text-muted2)] uppercase px-4 mb-2">Sources</div>
          {!sources.length ? (
            <div className="px-4 text-[12.5px] text-[var(--color-text-muted)] leading-relaxed">
              No sources reporting yet. A source appears once the relay forwards its first event.
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
                  className={`flex flex-col gap-0.5 py-[9px] px-4 cursor-pointer border-l-2 font-mono transition-colors
                    ${isActive ? 'border-[var(--color-brand-amber)] bg-[var(--color-panel-hi)]' : 'border-transparent hover:bg-[var(--color-panel-hi)]'}`}
                >
                  <div className="text-[12px] text-[var(--color-text-muted)]">{device}</div>
                  <div className="text-[12.5px] text-[var(--color-text-main)] truncate">{app}</div>
                </div>
              );
            })
          )}
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col min-w-0 bg-[var(--color-bg-base)] cyber-grid">
          <ScopePanel activeSource={activeSource} events={currentSourceEvents()} />
          <LogPanel events={currentSourceEvents()} activeSource={activeSource} />
        </main>
      </div>

      {/* Drawer */}
      <div className={`shrink-0 border-t border-[var(--color-border)] bg-[var(--color-panel)] flex flex-col transition-all duration-300 ${drawerOpen ? 'max-h-[34vh]' : 'max-h-[40px]'}`}>
        <div 
          className="flex items-center gap-2 px-5 py-2.5 cursor-pointer font-mono text-[11.5px] tracking-[0.08em] text-[var(--color-brand-red)] uppercase shrink-0 hover:bg-[var(--color-panel-hi)] transition-colors"
          onClick={() => setDrawerOpen(!drawerOpen)}
        >
          <span className={`transition-transform duration-200 ${drawerOpen ? 'rotate-180' : ''}`}>▲</span> 
          flagged events 
          <span className="bg-[var(--color-brand-red-dim)] text-[var(--color-brand-red)] rounded-[10px] px-2 py-[1px] text-[11px]">{flagged.length}</span>
        </div>
        <div className="overflow-y-auto px-5 pb-3">
          {!flagged.length ? (
            <div className="py-[9px] text-[var(--color-text-muted)] font-mono text-[12px]">nothing flagged — all sources within baseline</div>
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
    const h = 120;
    
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.height = h + 'px';
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    if (!events.length) return;

    const ordered = [...events].sort((a, b) => a.seq - b.seq);
    const n = ordered.length;
    const barGap = 2;
    const barW = Math.max(2, Math.min(10, w / n - barGap));
    const usableW = n * (barW + barGap);
    const startX = Math.max(0, w - usableW);

    // threshold line
    const thresholdY = h - THRESHOLD * (h - 10) - 5;
    ctx.strokeStyle = '#454c58';
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(w, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

    ordered.forEach((ev, i) => {
      const x = startX + i * (barW + barGap);
      const score = Math.max(0, Math.min(1, ev.ncd_score || 0));
      const barH = score * (h - 10);
      const y = h - barH - 5;
      ctx.fillStyle = score >= THRESHOLD ? '#ff4d4d' : '#ffa630';
      ctx.globalAlpha = score >= THRESHOLD ? 1 : 0.85;
      ctx.fillRect(x, y, barW, barH);
    });
    ctx.globalAlpha = 1;
  }, [events]);

  const idx = activeSource ? activeSource.indexOf(':') : -1;
  const device = idx === -1 ? activeSource : activeSource?.substring(0, idx);
  const app = idx === -1 ? "" : activeSource?.substring(idx + 1);
  const latest = events.length ? events.reduce((a, b) => (a.seq > b.seq ? a : b)) : null;
  const versionSuffix = latest && latest.app_version && latest.app_version !== 'unknown'
    ? ` · v${latest.app_version}`
    : '';

  return (
    <div className="border-b border-[var(--color-border)] px-5 pt-4 pb-3 shrink-0">
      <div className="flex items-baseline gap-2.5 mb-2.5">
        <div className="font-mono text-[13px] font-semibold">{activeSource ? `${device} · ${app}` : 'select a source'}</div>
        <div className="text-[11.5px] text-[var(--color-text-muted)] font-mono">
          {activeSource ? `${events.length} events in buffer · NCD vs. rolling baseline${versionSuffix}` : ''}
        </div>
      </div>
      <canvas ref={canvasRef} className="block w-full h-[120px] rounded bg-[#0d1017] border border-[var(--color-border)] shadow-inner" />
      <div className="flex gap-4 mt-2 font-mono text-[10.5px] text-[var(--color-text-muted)]">
        <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-sm bg-[var(--color-brand-amber)]" />normal</div>
        <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-sm bg-[var(--color-brand-red)]" />flagged (NCD &ge; 0.5, or rule match)</div>
        <div className="flex items-center gap-1.5"><div className="w-[14px] h-[1px] bg-[var(--color-text-muted2)]" />threshold</div>
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
      <div className="flex-1 overflow-y-auto px-5">
        <div className="flex flex-col items-center justify-center h-full gap-2 text-center p-10 text-[var(--color-text-muted)]">
          <div className="font-mono text-[13px] text-[var(--color-text-main)]">
            {activeSource ? 'no events for this source yet' : 'no events yet'}
          </div>
          <div className="text-[12px] max-w-[380px] leading-relaxed">
            Start driftnetd and run scripts/relay.py against a target app on the phone. Events will stream in here as the Frida agent hooks fire.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto px-5 pb-10">
      <div className="font-mono text-[10px] tracking-[0.12em] text-[var(--color-text-muted2)] uppercase py-3.5 pb-2 sticky top-0 bg-[var(--color-bg-base)] z-10 backdrop-blur-md">Event log</div>
      <table className="w-full border-collapse font-mono text-[12px]">
        <thead>
          <tr>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">seq</th>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">time</th>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">kind</th>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">ncd</th>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">rules</th>
            <th className="text-left font-medium text-[var(--color-text-muted)] px-2 py-1.5 border-b border-[var(--color-border)] text-[10.5px] tracking-[0.04em]">detail</th>
          </tr>
        </thead>
        <tbody>
          {displayEvents.map((ev) => (
            <tr key={ev.seq} className="hover:bg-[var(--color-panel-hi)] transition-colors group">
              <td className="px-2 py-1.5 border-b border-[#161a24] align-top text-[var(--color-text-muted)]">{ev.seq}</td>
              <td className="px-2 py-1.5 border-b border-[#161a24] align-top text-[var(--color-text-muted)]">{fmtTime(ev.timestamp)}</td>
              <td className="px-2 py-1.5 border-b border-[#161a24] align-top">
                <span className={`kind-tag kind-${ev.kind}`}>{ev.kind}</span>
              </td>
              <td className={`px-2 py-1.5 border-b border-[#161a24] align-top font-tabular-nums ${ev.ncd_score >= THRESHOLD ? 'text-[var(--color-brand-red)] font-semibold' : ''}`}>
                {(ev.ncd_score ?? 0).toFixed(3)}
              </td>
              <td className="px-2 py-1.5 border-b border-[#161a24] align-top">
                <RuleBadges matches={ev.rule_matches} />
              </td>
              <td className="px-2 py-1.5 border-b border-[#161a24] align-top text-[var(--color-text-muted)] max-w-[420px] truncate group-hover:text-[var(--color-text-main)] transition-colors">
                {summarizeDetail(ev.detail)}
              </td>
            </tr>
          ))}
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
    <div className="py-[9px] border-t border-[#1a1f2a] flex flex-col gap-1">
      <div className="flex items-center gap-2.5 font-mono text-[12px]">
        <span className="text-[var(--color-text-muted)]">#{ev.seq}</span>
        <span>{ev.device}:{ev.app}</span>
        <span className={`kind-tag kind-${ev.kind}`}>{ev.kind}</span>
        <span className="font-tabular-nums text-[var(--color-brand-red)]">{(ev.ncd_score ?? 0).toFixed(3)}</span>
        <RuleBadges matches={ev.rule_matches} />
        <span className="text-[var(--color-text-muted)]">{fmtTime(ev.timestamp)}</span>
        <button 
          onClick={onToggle}
          className="ml-auto font-mono text-[10.5px] text-[var(--color-brand-amber)] bg-transparent border border-[var(--color-brand-amber-dim)] rounded-[3px] px-1.5 py-[1px] cursor-pointer hover:bg-[var(--color-brand-amber-dim)] transition-colors"
        >
          why?
        </button>
      </div>
      <div className={`text-[12.5px] leading-[1.45] pl-[2px] ${ev.triage ? 'text-[var(--color-text-main)]' : 'text-[var(--color-text-muted)] italic'}`}>
        {ev.triage || 'triage pending…'}
      </div>
      {expanded && <AttrPanel attrs={ev.attribution} />}
    </div>
  );
}

function AttrPanel({ attrs }: { attrs: any[] }) {
  if (!attrs || !attrs.length) {
    return (
      <div className="mt-1.5 p-2 px-2.5 bg-[#0d1017] border border-[var(--color-border)] rounded text-[var(--color-text-muted)] italic font-mono text-[11px]">
        no field-level attribution for this event (empty/non-object detail, or it's a source's very first-ever event with no baseline to compare against)
      </div>
    );
  }

  const maxAbs = Math.max(...attrs.map(a => Math.abs(a.delta)), 0.001);

  return (
    <div className="mt-1.5 p-2 px-2.5 bg-[#0d1017] border border-[var(--color-border)] rounded font-mono text-[11px] shadow-inner">
      {attrs.map((a, i) => {
        const pct = Math.min(100, (Math.abs(a.delta) / maxAbs) * 100);
        return (
          <div key={i} className="flex items-center gap-2 py-0.5">
            <div className="w-[130px] shrink-0 text-[var(--color-text-muted)] truncate">{a.field}</div>
            <div className="flex-1 h-2.5 bg-[#161b26] rounded-sm overflow-hidden">
              <div 
                className={`h-full ${a.delta < 0 ? 'bg-[var(--color-text-muted2)]' : 'bg-[var(--color-brand-amber)]'}`} 
                style={{ width: `${pct}%` }} 
              />
            </div>
            <div className="w-[52px] shrink-0 text-right text-[var(--color-text-muted)]">
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
          return <span key={i} className="rule-badge rule-badge-info">updated {from} &rarr; {to}</span>;
        }
        if (r.startsWith('compressor_disagreement:')) {
          const parts = r.slice('compressor_disagreement:'.length);
          return <span key={i} className="rule-badge rule-badge-ambiguous" title="the two independent novelty measurements disagree">disagreement ({parts})</span>;
        }
        if (r.startsWith('secret_leak:')) {
          const pattern = r.slice('secret_leak:'.length);
          return <span key={i} className="rule-badge rule-badge-default" title="a redacted match only -- the actual secret value never left the device">leaked secret: {pattern}</span>;
        }
        if (r === 'insecure_intent') {
          return <span key={i} className="rule-badge rule-badge-vuln" title="implicit intent leaking sensitive data or granting URI permissions globally">⚠ insecure intent</span>;
        }
        if (r === 'insecure_sql_query') {
          return <span key={i} className="rule-badge rule-badge-vuln" title="unparameterized SQL query with concatenated values — potential SQL injection">⚠ sql injection risk</span>;
        }
        if (r === 'insecure_webview') {
          return <span key={i} className="rule-badge rule-badge-vuln" title="insecure WebView configuration: JS interface, mixed content, or file access">⚠ insecure webview</span>;
        }
        if (r === 'weak_biometric') {
          return <span key={i} className="rule-badge rule-badge-vuln" title="biometric auth without CryptoObject — result is a hookable boolean, trivially bypassable">⚠ weak biometric</span>;
        }
        return <span key={i} className="rule-badge rule-badge-default">{r}</span>;
      })}
    </>
  );
}

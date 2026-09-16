"use client";

import dynamic from 'next/dynamic';
import { useMemo, useRef, useState, useEffect } from 'react';

// Dynamically import ForceGraph3D to prevent SSR issues (document/window not defined)
const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), { ssr: false });

interface Event {
  device: string;
  app: string;
  kind: string;
  ncd_score: number;
  rule_matches: string[];
  detail: {
    fname?: string;
    pid?: number;
    uid?: number;
  };
}

export default function NervousGraph({ events, threshold = 0.5 }: { events: Event[], threshold?: number }) {
  const fgRef = useRef<any>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ width, height });
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo(() => {
    const nodesMap = new Map();
    const linksMap = new Map();

    nodesMap.set("Phone", { id: "Phone", group: "root", name: "Android Ring-0", val: 10, color: "#00f3ff" });

    // Deduplicate and process events
    events.forEach(ev => {
      const isAnomaly = ev.ncd_score >= threshold || (ev.rule_matches && ev.rule_matches.length > 0);
      const appNodeId = `app_${ev.app}`;
      
      if (!nodesMap.has(appNodeId)) {
        nodesMap.set(appNodeId, { id: appNodeId, group: "app", name: ev.app, val: 5, isAnomaly, color: isAnomaly ? "#ff003c" : "#ffffff" });
      } else if (isAnomaly) {
        nodesMap.get(appNodeId).isAnomaly = true;
        nodesMap.get(appNodeId).color = "#ff003c";
        nodesMap.get(appNodeId).val = 8;
      }
      
      const linkId1 = `Phone->${appNodeId}`;
      if (!linksMap.has(linkId1)) {
        linksMap.set(linkId1, { source: "Phone", target: appNodeId, isAnomaly, color: isAnomaly ? "rgba(255, 0, 60, 0.8)" : "rgba(0, 243, 255, 0.3)" });
      } else if (isAnomaly) {
        linksMap.get(linkId1).color = "rgba(255, 0, 60, 0.8)";
        linksMap.get(linkId1).isAnomaly = true;
      }

      if (ev.detail && ev.detail.fname) {
        let targetName = ev.detail.fname;
        let group = "file";
        if (targetName.startsWith("IP:")) group = "network";
        if (targetName.startsWith("EXEC:")) group = "process";
        
        const targetNodeId = `target_${targetName}`;
        if (!nodesMap.has(targetNodeId)) {
          nodesMap.set(targetNodeId, { id: targetNodeId, group, name: targetName, val: 2, isAnomaly, color: isAnomaly ? "#ff003c" : "rgba(255,255,255,0.4)" });
        } else if (isAnomaly) {
          nodesMap.get(targetNodeId).isAnomaly = true;
          nodesMap.get(targetNodeId).color = "#ff003c";
        }
        
        const linkId2 = `${appNodeId}->${targetNodeId}`;
        if (!linksMap.has(linkId2)) {
          linksMap.set(linkId2, { source: appNodeId, target: targetNodeId, isAnomaly, color: isAnomaly ? "rgba(255, 0, 60, 0.8)" : "rgba(255,255,255,0.1)" });
        } else if (isAnomaly) {
          linksMap.get(linkId2).color = "rgba(255, 0, 60, 0.8)";
          linksMap.get(linkId2).isAnomaly = true;
        }
      }
    });

    return {
      nodes: Array.from(nodesMap.values()),
      links: Array.from(linksMap.values())
    };
  }, [events, threshold]);

  return (
    <div ref={containerRef} className="w-full h-full bg-[#080a0f] relative overflow-hidden rounded-lg shadow-[inset_0_0_50px_rgba(0,243,255,0.05)]">
      {/* Decorative HUD Elements */}
      <div className="absolute top-4 left-4 z-10 font-mono text-[11px] text-[var(--color-brand-cyan)] tracking-[0.2em] font-bold opacity-70">
        NERVOUS SYSTEM TOPOLOGY
      </div>
      <div className="absolute top-4 right-4 z-10 flex gap-2">
        <span className="flex items-center gap-2 font-mono text-[10px] text-white/50"><div className="w-2 h-2 rounded-full bg-[#00f3ff]"></div> KERNEL</span>
        <span className="flex items-center gap-2 font-mono text-[10px] text-white/50"><div className="w-2 h-2 rounded-full bg-white"></div> PROCESS</span>
        <span className="flex items-center gap-2 font-mono text-[10px] text-[var(--color-brand-crimson)] font-bold"><div className="w-2 h-2 rounded-full bg-[var(--color-brand-crimson)] shadow-[0_0_8px_var(--color-brand-crimson)]"></div> THREAT</span>
      </div>

      <ForceGraph3D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        nodeLabel="name"
        nodeColor="color"
        nodeVal="val"
        linkColor="color"
        linkWidth={(link: any) => link.isAnomaly ? 2 : 0.5}
        nodeRelSize={4}
        linkDirectionalParticles={(link: any) => link.isAnomaly ? 4 : 2}
        linkDirectionalParticleWidth={(link: any) => link.isAnomaly ? 2.5 : 1}
        linkDirectionalParticleSpeed={0.015}
        enableNodeDrag={false}
        backgroundColor="#080a0f"
      />
    </div>
  );
}

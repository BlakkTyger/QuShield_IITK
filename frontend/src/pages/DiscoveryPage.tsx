import { useState, useMemo, useCallback } from 'react';
import { useDiscoverySummary, useDiscoveryDomains, useDiscoveryGraph } from '../hooks/useDiscovery';
import MetricCard from '../components/MetricCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { Globe, Lock, Network, Cpu, Cloud, MonitorSmartphone, KeyRound, ShieldCheck, AlertTriangle, ShieldAlert } from 'lucide-react';
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

const NODE_COLORS: Record<string, string> = {
  domain: '#FBBC09',
  ip: '#A20E37',
  certificate: '#22C55E',
  dns: '#3B82F6',
  default: '#6B7092',
};

export default function DiscoveryPage() {
  const [activeTab, setActiveTab] = useState<'domains' | 'graph'>('domains');
  const { data: summary, isLoading: summaryLoading } = useDiscoverySummary();
  const { data: domains, isLoading: domainsLoading } = useDiscoveryDomains();
  const { data: graphData } = useDiscoveryGraph();

  // Convert graph data for React Flow
  const flowNodes: Node[] = useMemo(() => {
    if (!graphData?.nodes) return [];
    const spacing = 250;
    const cols = Math.ceil(Math.sqrt(graphData.nodes.length));
    return graphData.nodes.map((n, i) => ({
      id: n.id,
      data: { label: n.label },
      position: { x: (i % cols) * spacing + 50, y: Math.floor(i / cols) * 120 + 50 },
      style: {
        background: '#1E2133',
        border: `2px solid ${NODE_COLORS[n.type] || NODE_COLORS.default}`,
        borderRadius: 10,
        color: '#F0F0F5',
        padding: '8px 14px',
        fontSize: '0.8rem',
        fontFamily: 'Inter, sans-serif',
      },
    }));
  }, [graphData]);

  const flowEdges: Edge[] = useMemo(() => {
    if (!graphData?.edges) return [];
    return graphData.edges.map((e, i) => ({
      id: `edge-${i}`,
      source: e.source,
      target: e.target,
      label: e.relationship,
      animated: true,
      style: { stroke: '#6B7092', strokeWidth: 1.5 },
      labelStyle: { fill: '#A0A4B8', fontSize: 10, fontFamily: 'Inter' },
      labelBgStyle: { fill: '#161924', fillOpacity: 0.9 },
      labelBgPadding: [4, 6] as [number, number],
      labelBgBorderRadius: 4,
    }));
  }, [graphData]);

  const onInit = useCallback(() => { }, []);

  if (summaryLoading) return <LoadingSpinner />;

  return (
    <div className="animate-fadeIn">
      <div className="page-header">
        <h2>Asset Discovery</h2>
        <p>Discover and map your organization's digital assets</p>
      </div>

      {/* Summary Cards */}
      <div className="metrics-grid">
        <MetricCard icon={<Globe size={22} />} label="Domains" value={summary?.domains_count ?? 0} variant="gold" />
        <MetricCard icon={<Lock size={22} />} label="SSL Certificates" value={summary?.ssl_certs_count ?? 0} variant="success" />
        <MetricCard icon={<Network size={22} />} label="IP/Subnets" value={summary?.ip_subnets_count ?? 0} variant="maroon" />
        <MetricCard icon={<ShieldCheck size={22} />} label="Quantum Safe" value={summary?.quantum_safe ?? 0} variant="success" />
      </div>

      <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <MetricCard icon={<Lock size={22} />} label="Hybrid Assets" value={summary?.hybrid ?? 0} variant="info" />
        <MetricCard icon={<AlertTriangle size={22} />} label="Vulnerable" value={summary?.vulnerable ?? 0} variant="warning" />
        <MetricCard icon={<ShieldAlert size={22} />} label="Critical" value={summary?.critical ?? 0} variant="danger" />
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button className={`tab ${activeTab === 'domains' ? 'active' : ''}`} onClick={() => setActiveTab('domains')}>
          Domains <span className="tab-count">{domains?.total ?? 0}</span>
        </button>
        <button className={`tab ${activeTab === 'graph' ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>
          Relationship Graph
        </button>
      </div>

      {/* Domain Table */}
      {activeTab === 'domains' && (
        domainsLoading ? <LoadingSpinner /> : (
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>FQDN</th>
                  <th>IP Address</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Risk Level</th>
                  <th>Detection Date</th>
                </tr>
              </thead>
              <tbody>
                {domains?.items && domains.items.length > 0 ? (
                  domains.items.map((d) => (
                    <tr key={d.id}>
                      <td className="td-primary">{d.fqdn}</td>
                      <td>{d.ipv4_address || '—'}</td>
                      <td>{d.asset_type || '—'}</td>
                      <td>
                        <span className={`badge ${d.status === 'confirmed' ? 'success' :
                            d.status === 'new' ? 'info' : 'warning'
                          }`}>{d.status || 'new'}</span>
                      </td>
                      <td>
                        <span className={`badge ${d.risk_level || 'info'}`}>{d.risk_level || 'unknown'}</span>
                      </td>
                      <td style={{ fontSize: '0.82rem' }}>
                        {d.detection_date ? new Date(d.detection_date).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6}>
                      <div className="empty-state">
                        <Globe size={40} />
                        <h3>No Domains Discovered</h3>
                        <p>Run a scan to discover domains</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Graph View */}
      {activeTab === 'graph' && (
        <div className="chart-card" style={{ height: 500, padding: 0, overflow: 'hidden' }}>
          {flowNodes.length > 0 ? (
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              onInit={onInit}
              fitView
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#242838" gap={20} />
              <Controls />
            </ReactFlow>
          ) : (
            <div className="empty-state" style={{ height: '100%' }}>
              <Network size={48} />
              <h3>No Graph Data</h3>
              <p>Run a scan with discovery enabled to see the relationship graph</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

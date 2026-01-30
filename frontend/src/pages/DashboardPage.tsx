import { useDashboardMetrics, useRiskDistribution } from '../hooks/useDashboard';
import { useEnterpriseRating } from '../hooks/useRating';
import MetricCard from '../components/MetricCard';
import ScoreGauge from '../components/ScoreGauge';
import LoadingSpinner from '../components/LoadingSpinner';
import { Server, ShieldCheck, AlertTriangle, ShieldAlert, Award, Clock, Lock, Wifi } from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const RISK_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#22C55E',
  unknown: '#6B7092',
};

const SAFETY_COLORS: Record<string, string> = {
  FULLY_SAFE: '#22C55E',
  HYBRID: '#A855F7',
  VULNERABLE: '#F59E0B',
  CRITICAL: '#EF4444',
  QUANTUM_VULNERABLE: '#F59E0B',
  unknown: '#6B7092',
};

export default function DashboardPage() {
  const { data: metrics, isLoading: metricsLoading } = useDashboardMetrics();
  const { data: riskDist, isLoading: riskLoading } = useRiskDistribution();
  const { data: rating } = useEnterpriseRating();

  if (metricsLoading) return <LoadingSpinner />;

  const m = metrics;

  return (
    <div className="animate-fadeIn">
      <div className="page-header">
        <h2>Security Overview</h2>
        <p>
          {m?.last_scan_domain
            ? `Latest scan: ${m.last_scan_domain}`
            : 'Run a scan to see your security posture'}
        </p>
      </div>

      {/* ── Metrics Row ──────────────────────────────────── */}
      <div className="metrics-grid">
        <MetricCard
          icon={<Server size={22} />}
          label="Discovered Assets"
          value={m?.asset_counts?.total_assets ?? 0}
          variant="gold"
        />
        <MetricCard
          icon={<ShieldCheck size={22} />}
          label="Quantum Safe"
          value={m?.quantum_safety?.quantum_safe ?? 0}
          variant="success"
        />
        <MetricCard
          icon={<AlertTriangle size={22} />}
          label="Vulnerable"
          value={m?.quantum_safety?.vulnerable ?? 0}
          variant="warning"
        />
        <MetricCard
          icon={<ShieldAlert size={22} />}
          label="Critical"
          value={m?.quantum_safety?.critical ?? 0}
          variant="danger"
        />
      </div>

      {/* ── Score + Charts Row ────────────────────────────── */}
      <div className="charts-grid" style={{ gridTemplateColumns: '1fr 2fr' }}>
        {/* Enterprise Score */}
        <div className="chart-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div className="chart-title" style={{ alignSelf: 'flex-start' }}>Enterprise Cyber Rating</div>
          <ScoreGauge
            score={rating?.enterprise_score ?? m?.enterprise_score ?? 0}
            category={rating?.category ?? m?.rating_category ?? 'Legacy'}
          />
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 8 }}>
            HNDL Risk Score: <span style={{ color: 'var(--pnb-gold)', fontWeight: 700 }}>
              {(m?.average_hndl_score ?? 0).toFixed(2)}
            </span>
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="chart-card">
          <div className="chart-title">Risk Distribution</div>
          {riskLoading ? (
            <LoadingSpinner />
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18, height: 260 }}>
              {/* Risk Level Pie */}
              <div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>
                  By Risk Level
                </div>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={riskDist?.risk_levels ?? []}
                      dataKey="count"
                      nameKey="label"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={45}
                      paddingAngle={3}
                    >
                      {riskDist?.risk_levels?.map((item) => (
                        <Cell key={item.label} fill={RISK_COLORS[item.label] || '#6B7092'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                      itemStyle={{ color: '#F0F0F5' }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: '0.72rem' }}
                      formatter={(value) => <span style={{ color: '#A0A4B8' }}>{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Quantum Safety Bar */}
              <div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>
                  Quantum Safety
                </div>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={riskDist?.quantum_safety ?? []} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                    <XAxis type="number" />
                    <YAxis type="category" dataKey="label" width={90} tick={{ fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                      itemStyle={{ color: '#F0F0F5' }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {riskDist?.quantum_safety?.map((item) => (
                        <Cell key={item.label} fill={SAFETY_COLORS[item.label] || '#6B7092'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Secondary Metrics ─────────────────────────────── */}
      <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <MetricCard
          icon={<Server size={20} />}
          label="IPv4 Addresses"
          value={m?.ip_breakdown?.ipv4_count ?? 0}
          variant="gold"
        />
        <MetricCard
          icon={<Server size={20} />}
          label="IPv6 Addresses"
          value={m?.ip_breakdown?.ipv6_count ?? 0}
          variant="warning"
        />
        <MetricCard
          icon={<Clock size={20} />}
          label="Expiring (30d)"
          value={m?.cert_expiry?.expiring_30d ?? 0}
          variant="danger"
        />
        <MetricCard
          icon={<Lock size={20} />}
          label="Hybrid Assets"
          value={m?.quantum_safety?.hybrid ?? 0}
          variant="info"
        />
      </div>

      {/* ── IP & Asset Breakdown + High Risk Table ─────── */}
      <div className="charts-grid">
        {/* IP Breakdown */}
        <div className="chart-card">
          <div className="chart-title">IP Address Breakdown</div>
          <div style={{ display: 'flex', gap: 24, alignItems: 'center', padding: '16px 0' }}>
            <div style={{ flex: 1 }}>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'IPv4', value: m?.ip_breakdown?.ipv4_count ?? 0 },
                      { name: 'IPv6', value: m?.ip_breakdown?.ipv6_count ?? 0 },
                    ]}
                    dataKey="value"
                    cx="50%"
                    cy="50%"
                    outerRadius={60}
                    innerRadius={35}
                  >
                    <Cell fill="#FBBC09" />
                    <Cell fill="#A20E37" />
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                    itemStyle={{ color: '#F0F0F5' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="flex items-center gap-sm">
                <Wifi size={16} color="#FBBC09" />
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  IPv4: <strong style={{ color: 'var(--text-primary)' }}>{m?.ip_breakdown?.ipv4_count ?? 0}</strong>
                  <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>({m?.ip_breakdown?.ipv4_percent ?? 0}%)</span>
                </span>
              </div>
              <div className="flex items-center gap-sm">
                <Wifi size={16} color="#A20E37" />
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  IPv6: <strong style={{ color: 'var(--text-primary)' }}>{m?.ip_breakdown?.ipv6_count ?? 0}</strong>
                  <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>({m?.ip_breakdown?.ipv6_percent ?? 0}%)</span>
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* High Risk Assets */}
        <div className="chart-card">
          <div className="chart-title">High Risk Assets</div>
          {riskDist?.high_risk_assets && riskDist.high_risk_assets.length > 0 ? (
            <div className="data-table-wrapper" style={{ border: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Risk</th>
                    <th>HNDL</th>
                    <th>Safety</th>
                  </tr>
                </thead>
                <tbody>
                  {riskDist.high_risk_assets.map((a) => (
                    <tr key={a.id}>
                      <td className="td-primary">{a.fqdn}</td>
                      <td>
                        <span className={`badge ${a.risk_level}`}>{a.risk_level}</span>
                      </td>
                      <td>{a.hndl_score?.toFixed(2) ?? '—'}</td>
                      <td>
                        <span className={`badge ${a.quantum_safety === 'FULLY_SAFE' ? 'quantum-safe' :
                          a.quantum_safety === 'HYBRID' ? 'hybrid' :
                            a.quantum_safety === 'CRITICAL' ? 'critical' : 'vulnerable'
                          }`}>
                          {a.quantum_safety ?? 'Unknown'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={40} />
              <h3>No High Risk Assets</h3>
              <p>All assets are within acceptable risk levels</p>
            </div>
          )}
        </div>
      </div>

      {/* ── Mosca's Theorem Visualization ──────────────────── */}
      {riskDist?.mosca_assets && riskDist.mosca_assets.length > 0 && (
        <div className="chart-card mb-lg mt-lg">
          <div className="chart-title">Mosca's Theorem Analysis (D + T ≥ Z)</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: 20 }}>
            If Data Shelf-Life (D) + Migration Time (T) exceeds the Quantum Threat Horizon (Z), the asset is at risk of Harvest Now, Decrypt Later (HNDL).
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={riskDist.mosca_assets.slice(0, 8)} margin={{ top: 10, right: 10, left: 10, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="fqdn" tick={{ fontSize: 10 }} angle={-20} textAnchor="end" />
              <YAxis tick={{ fontSize: 11 }} label={{ value: 'Years', angle: -90, position: 'insideLeft', fill: '#6B7092' }} />
              <Tooltip
                contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                itemStyle={{ color: '#F0F0F5' }}
              />
              <Legend wrapperStyle={{ fontSize: '0.8rem', paddingTop: '10px' }} />
              <Bar dataKey="d_years" name="Data Shelf-Life (D)" stackId="a" fill="#3B82F6" radius={[0, 0, 4, 4]} />
              <Bar dataKey="t_years" name="Migration Time (T)" stackId="a" fill="#F59E0B" radius={[4, 4, 0, 0]} />
              <Bar dataKey="z_years" name="Threat Horizon (Z)" fill="#22C55E" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* ── Asset Types ───────────────────────────────────── */}
      {riskDist?.asset_types && riskDist.asset_types.length > 0 && (
        <div className="chart-card mb-lg">
          <div className="chart-title">Asset Type Distribution</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={riskDist.asset_types}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                itemStyle={{ color: '#F0F0F5' }}
              />
              <Bar dataKey="count" fill="#A20E37" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

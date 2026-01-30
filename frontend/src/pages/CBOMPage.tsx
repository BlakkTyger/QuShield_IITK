import { useCBOMMetrics, useExportCBOM } from '../hooks/useCBOM';
import MetricCard from '../components/MetricCard';
import LoadingSpinner from '../components/LoadingSpinner';
import { Database, ShieldAlert, KeyRound, AlertTriangle, Download, FileJson } from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts';

export default function CBOMPage() {
  const { data: metrics, isLoading } = useCBOMMetrics();
  const { exportCBOM } = useExportCBOM();

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="animate-fadeIn">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Cryptographic Bill of Materials (CBOM)</h2>
          <p>CycloneDX 1.6 compliant software and cryptographic asset inventory</p>
        </div>
        <button 
          className="btn btn-gold" 
          onClick={() => exportCBOM()}
        >
          <Download size={18} />
          Export CBOM
        </button>
      </div>

      {/* Metrics */}
      <div className="metrics-grid">
        <MetricCard icon={<Database size={22} />} label="Total Applications" value={metrics?.total_applications ?? 0} variant="gold" />
        <MetricCard icon={<KeyRound size={22} />} label="Active Certificates" value={metrics?.active_certificates ?? 0} variant="success" />
        <MetricCard icon={<ShieldAlert size={22} />} label="Weak Crypto Count" value={metrics?.weak_crypto_count ?? 0} variant="danger" />
        <MetricCard icon={<AlertTriangle size={22} />} label="Certificate Issues" value={metrics?.certificate_issues ?? 0} variant="warning" />
      </div>

      <div className="charts-grid">
        {/* Cipher Usage */}
        <div className="chart-card">
          <div className="chart-title">Cipher Suite Usage</div>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={metrics?.cipher_usage ?? []}
                dataKey="count"
                nameKey="cipher"
                cx="50%"
                cy="50%"
                outerRadius={90}
                innerRadius={50}
                paddingAngle={2}
              >
                {metrics?.cipher_usage?.map((item, index) => (
                  <Cell key={item.cipher} fill={['#FBBC09', '#A20E37', '#3B82F6', '#22C55E', '#A855F7', '#F59E0B'][index % 6]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                itemStyle={{ color: '#F0F0F5' }}
              />
              <Legend wrapperStyle={{ fontSize: '0.72rem' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Key Lengths */}
        <div className="chart-card">
          <div className="chart-title">Key Length Distribution</div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={metrics?.key_length_distribution ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="key_length" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                itemStyle={{ color: '#F0F0F5' }}
              />
              <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* TLS Versions */}
        <div className="chart-card">
          <div className="chart-title">TLS Version Distribution</div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={metrics?.tls_version_distribution ?? []} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis type="number" />
              <YAxis type="category" dataKey="version" width={70} tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                itemStyle={{ color: '#F0F0F5' }}
              />
              <Bar dataKey="count" fill="#22C55E" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top CAs */}
        <div className="chart-card">
          <div className="chart-title">Top Certificate Authorities</div>
          <div className="data-table-wrapper" style={{ border: 'none', maxHeight: 260, overflowY: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>CA Name</th>
                  <th>Count</th>
                  <th>%</th>
                </tr>
              </thead>
              <tbody>
                {metrics?.top_cas?.map((ca) => (
                  <tr key={ca.ca_name}>
                    <td className="td-primary" style={{ fontSize: '0.8rem' }}>{ca.ca_name}</td>
                    <td>{ca.count}</td>
                    <td>{ca.percentage}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="card mt-lg" style={{ display: 'flex', alignItems: 'center', gap: 20, background: 'var(--bg-elevated)' }}>
        <FileJson size={40} color="#FBBC09" />
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: 4 }}>Need Raw Data?</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            Export the complete Cryptographic Bill of Materials in CycloneDX 1.6 format with the CERT-In QBOM extension to ingest into your compliance tools.
          </p>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="btn btn-outline" onClick={() => exportCBOM()}>Download JSON</button>
        </div>
      </div>
    </div>
  );
}

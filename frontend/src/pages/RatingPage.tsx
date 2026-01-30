import { useEnterpriseRating, useAssetRatings } from '../hooks/useRating';
import ScoreGauge from '../components/ScoreGauge';
import LoadingSpinner from '../components/LoadingSpinner';
import { Activity, ShieldAlert } from 'lucide-react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Tooltip
} from 'recharts';

export default function RatingPage() {
  const { data: rating, isLoading: ratingLoading } = useEnterpriseRating();
  const { data: assetRatings, isLoading: assetsLoading } = useAssetRatings();

  if (ratingLoading) return <LoadingSpinner />;

  // Transform breakdown for radar chart
  const radarData = rating?.breakdown ? [
    { subject: 'Quantum Safety', A: Math.round(rating.breakdown.quantum_safety.score * 100), fullMark: 100 },
    { subject: 'Cert Health', A: Math.round(rating.breakdown.certificate_health.score * 100), fullMark: 100 },
    { subject: 'Protocol', A: Math.round(rating.breakdown.protocol_strength.score * 100), fullMark: 100 },
    { subject: 'HNDL Risk', A: Math.round(rating.breakdown.hndl_risk.score * 100), fullMark: 100 },
  ] : [];

  return (
    <div className="animate-fadeIn">
      <div className="page-header">
        <h2>Cyber Rating</h2>
        <p>Enterprise and per-asset security scores based on Post-Quantum readiness</p>
      </div>

      <div className="charts-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        {/* Enterprise Score */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div className="chart-title" style={{ alignSelf: 'flex-start', marginBottom: 20 }}>Consolidated Enterprise-Level Cyber-Rating Score</div>
          <ScoreGauge
            score={rating?.enterprise_score ?? 0}
            category={rating?.category ?? 'Legacy'}
            size={280}
          />
          <div style={{ marginTop: 24, padding: '16px 24px', background: 'var(--bg-elevated)', borderRadius: 12, border: '1px solid var(--border-color)', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
             <div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Status</div>
                <div style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                   PQC Rating For Enterprise
                </div>
             </div>
             <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Maximum Score*</div>
                <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--pnb-gold)' }}>1000</div>
             </div>
          </div>
        </div>

        {/* Breakdown Radar */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="chart-title">Score Breakdown</div>
          <div style={{ flex: 1, minHeight: 400 }}>
            {radarData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                  <PolarGrid stroke="rgba(255,255,255,0.1)" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#A0A4B8', fontSize: 12 }} />
                  <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ background: '#242838', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10 }}
                    itemStyle={{ color: '#F0F0F5' }}
                  />
                  <Radar name="Score" dataKey="A" stroke="#FBBC09" fill="#FBBC09" fillOpacity={0.4} />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">
                <ShieldAlert size={40} />
                <p>No breakdown data available</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="charts-grid" style={{ gridTemplateColumns: '2fr 1fr' }}>
        {/* Asset Ratings */}
        <div className="card">
          <div className="chart-title">Asset Ratings ({assetRatings?.total ?? 0})</div>
          {assetsLoading ? <LoadingSpinner /> : (
            <div className="data-table-wrapper" style={{ border: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset (URL)</th>
                    <th>PQC Score</th>
                    <th>Category</th>
                    <th>Safety</th>
                  </tr>
                </thead>
                <tbody>
                  {assetRatings?.items && assetRatings.items.length > 0 ? (
                    assetRatings.items.slice(0, 10).map((a) => (
                      <tr key={a.id}>
                        <td className="td-primary">{a.fqdn}</td>
                        <td style={{ fontWeight: 700, color: 'var(--pnb-gold)' }}>{a.score}</td>
                        <td>
                          <span className={`badge ${
                            a.category === 'Elite' ? 'elite' :
                            a.category === 'Standard' ? 'standard' : 'legacy'
                          }`}>
                            {a.category}
                          </span>
                        </td>
                         <td>
                           <span className={`badge ${
                             a.quantum_safety === 'FULLY_SAFE' ? 'quantum-safe' :
                             a.quantum_safety === 'HYBRID' ? 'hybrid' :
                             a.quantum_safety === 'CRITICAL' ? 'critical' : 'vulnerable'
                           }`}>
                             {a.quantum_safety || 'Unknown'}
                           </span>
                         </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={4}>
                        <div className="empty-state">
                          <Activity size={32} />
                          <p>No asset ratings available</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Rating Tiers Legend */}
        <div className="card">
          <div className="chart-title">Rating Tiers Legend</div>
          <table className="tier-table" style={{ fontSize: '0.85rem' }}>
             <thead>
                <tr>
                   <th>Status</th>
                   <th>Score Range</th>
                </tr>
             </thead>
             <tbody>
                <tr>
                   <td>
                      <div className="tier-indicator">
                         <div className="tier-dot elite"></div> Elite-PQC
                      </div>
                   </td>
                   <td style={{ fontWeight: 600 }}>&gt; 700</td>
                </tr>
                <tr>
                   <td>
                      <div className="tier-indicator">
                         <div className="tier-dot standard"></div> Standard
                      </div>
                   </td>
                   <td style={{ fontWeight: 600 }}>400 to 700</td>
                </tr>
                <tr>
                   <td>
                      <div className="tier-indicator">
                         <div className="tier-dot legacy"></div> Legacy
                      </div>
                   </td>
                   <td style={{ fontWeight: 600 }}>&lt; 400</td>
                </tr>
             </tbody>
          </table>
          <div style={{ marginTop: 24, padding: 16, background: 'var(--pnb-maroon-light)', borderRadius: 8, border: '1px solid var(--pnb-maroon)' }}>
             <h4 style={{ color: 'var(--pnb-maroon)', fontSize: '0.85rem', marginBottom: 4 }}>Note</h4>
             <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                Elite status indicates a strongly compliant post-quantum security posture as per NIST guidelines (FIPS 203/204/205).
             </p>
          </div>
        </div>
      </div>
    </div>
  );
}

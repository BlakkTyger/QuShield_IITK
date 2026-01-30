import { usePostureSummary, useRecommendations, usePQCCertificates } from '../hooks/usePosture';
import { ShieldCheck, AlertTriangle, Info, HardDrive, CheckCircle2, AlertOctagon } from 'lucide-react';
import LoadingSpinner from '../components/LoadingSpinner';

export default function PosturePage() {
  const { data: summary, isLoading: reqLoading1 } = usePostureSummary();
  const { data: recs, isLoading: reqLoading2 } = useRecommendations();
  const { isLoading: reqLoading3 } = usePQCCertificates();

  const isLoading = reqLoading1 || reqLoading2 || reqLoading3;

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="animate-fadeIn">
      <div className="page-header">
        <h2>PQC Posture</h2>
        <p>Post-Quantum Cryptography compliance and remediation</p>
      </div>

      <div className="card mb-lg">
        <div className="chart-title mb-md">PQC Adoption Progress</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div className="progress-bar" style={{ flex: 1, height: 12 }}>
            <div 
              className="progress-fill" 
              style={{ width: `${summary?.pqc_adoption_progress ?? 0}%` }} 
            />
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--pnb-gold)' }}>
            {summary?.pqc_adoption_progress?.toFixed(1) ?? '0.0'}%
          </div>
        </div>
      </div>

      {/* Compliance Target section */}
      <div className="charts-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="card">
          <div className="chart-title">Compliance Target</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20, paddingTop: 10 }}>
            {summary?.compliance_status === 'COMPLIANT' ? (
              <CheckCircle2 color="var(--color-success)" size={48} />
            ) : summary?.compliance_status === 'PARTIAL' ? (
              <AlertTriangle color="var(--color-warning)" size={48} />
            ) : (
              <AlertOctagon color="var(--color-danger)" size={48} />
            )}
            
            <div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Status</div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800 }}>
                {summary?.compliance_status ?? 'Unknown'}
              </div>
            </div>
            
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
               <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Migration Priority</div>
               <div className={`badge ${summary?.migration_priority?.toLowerCase() || ''}`}>
                 {summary?.migration_priority ?? 'Unknown'}
               </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="chart-title mb-md">Assets by Classification Grade</div>
          <div className="classification-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, margin: 0 }}>
            <div className="classification-card">
              <div className="classification-count text-success">{summary?.elite_count ?? 0}</div>
              <div className="classification-label">Elite</div>
            </div>
            <div className="classification-card">
              <div className="classification-count text-warning">{summary?.standard_count ?? 0}</div>
              <div className="classification-label">Standard</div>
            </div>
            <div className="classification-card">
              <div className="classification-count text-danger">{summary?.legacy_count ?? 0}</div>
              <div className="classification-label">Legacy</div>
            </div>
            <div className="classification-card" style={{ borderColor: 'var(--color-danger)', background: 'rgba(239, 68, 68, 0.05)' }}>
              <div className="classification-count text-danger">{summary?.critical_count ?? 0}</div>
              <div className="classification-label">Critical</div>
            </div>
          </div>
        </div>
      </div>

      <div className="charts-grid" style={{ gridTemplateColumns: '2fr 3fr' }}>
        <div>
           {/* Certification Tiers Spec */}
           <div className="card" style={{ height: '100%' }}>
             <div className="chart-title">Compliance Criteria</div>
             <table className="tier-table" style={{ fontSize: '0.8rem' }}>
              <thead>
                <tr>
                  <th>Tier</th>
                  <th>Level</th>
                  <th>Priority/Action</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><div className="tier-indicator"><div className="tier-dot elite"></div>1 (Elite)</div></td>
                  <td>FULLY_QUANTUM_SAFE</td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Maintain Configuration; periodic monitoring</td>
                </tr>
                <tr>
                  <td><div className="tier-indicator"><div className="tier-dot standard"></div>2 (Standard)</div></td>
                  <td>PQC_READY</td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Improve gradually; disable legacy</td>
                </tr>
                <tr>
                  <td><div className="tier-indicator"><div className="tier-dot legacy"></div>3 (Legacy)</div></td>
                  <td>QUANTUM_VULNERABLE</td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Remediation required; rotate certificates</td>
                </tr>
                <tr>
                   <td><div className="tier-indicator"><div className="tier-dot critical"></div>Critical</div></td>
                   <td>VULNERABLE / BROKEN</td>
                   <td style={{ fontSize: '0.75rem', color: 'var(--color-danger)' }}>Immediate action block or isolate</td>
                </tr>
              </tbody>
             </table>
           </div>
        </div>

        <div>
           {/* Recommendations */}
           <div className="card" style={{ height: '100%' }}>
            <div className="chart-title">Remediation Recommendations</div>
            {recs?.items && recs.items.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {recs.items.map(rec => (
                  <div key={rec.id} style={{ 
                    padding: 16, 
                    borderRadius: 'var(--radius-md)', 
                    border: '1px solid var(--border-color)',
                    background: 'var(--bg-elevated)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 16
                  }}>
                     <div style={{ paddingTop: 4 }}>
                       {rec.priority === 'critical' ? <AlertOctagon size={20} color="var(--color-danger)" /> :
                        rec.priority === 'high' ? <AlertTriangle size={20} color="var(--color-warning)" /> :
                        rec.priority === 'medium' ? <Info size={20} color="var(--color-info)" /> : 
                        <HardDrive size={20} color="var(--text-muted)" />}
                     </div>
                     <div style={{ flex: 1 }}>
                       <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                          <h4 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>{rec.title}</h4>
                          <span className={`badge ${rec.priority}`}>{rec.priority}</span>
                       </div>
                       <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 8 }}>{rec.description}</p>
                       <div style={{ fontSize: '0.75rem', background: 'var(--bg-input)', padding: '6px 10px', borderRadius: 4, color: 'var(--pnb-gold)' }}>
                         <strong>Action:</strong> {rec.action}
                       </div>
                     </div>
                  </div>
                ))}
              </div>
            ) : (
               <div className="empty-state">
                  <ShieldCheck size={32} />
                  <p>No recommendations at this time.</p>
               </div>
            )}
           </div>
        </div>
      </div>

    </div>
  );
}

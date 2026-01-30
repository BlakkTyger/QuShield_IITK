import { useState } from 'react';
import { useScans, useTriggerScan, useScanStatus } from '../hooks/useScans';
import { Search, Loader2, Play, CheckCircle2, XCircle, Clock } from 'lucide-react';
import LoadingSpinner from '../components/LoadingSpinner';

export default function ScansPage() {
   const [page] = useState(1);
   const { data: scans, isLoading } = useScans(page, 20);
   const triggerScan = useTriggerScan();
   const [activeScanId, setActiveScanId] = useState<string | null>(null);

   // Refetch scans list if active scan completes
   const { data: activeStatus } = useScanStatus(activeScanId);

   const [domain, setDomain] = useState('');
   const [maxAssets, setMaxAssets] = useState(50);
   const [skipDiscovery, setSkipDiscovery] = useState(false);

   const handleTrigger = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!domain) return;

      try {
         const result = await triggerScan.mutateAsync({
            domain,
            max_assets: maxAssets,
            skip_discovery: skipDiscovery
         });
         setActiveScanId(result.id);
         setDomain('');
      } catch (err) {
         console.error('Failed to trigger scan', err);
      }
   };

   return (
      <div className="animate-fadeIn">
         <div className="page-header">
            <h2>Scan Management</h2>
            <p>Trigger new security assessments and monitor progress</p>
         </div>

         {/* New Scan Form - Styled like the prototype search bar */}
         <div className="card mb-lg" style={{ background: 'linear-gradient(to right, var(--bg-card), rgba(162, 14, 55, 0.1))', borderColor: 'rgba(162, 14, 55, 0.2)' }}>
            <div className="chart-title mb-md" style={{ color: 'var(--text-primary)' }}>Initiate New Scan</div>
            <form onSubmit={handleTrigger} style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
               <div className="search-bar" style={{ flex: 2, minWidth: 280, background: 'var(--bg-elevated)' }}>
                  <Search size={18} color="var(--pnb-gold)" />
                  <input
                     type="text"
                     placeholder="Search domain, URL, IP Address or IoC"
                     value={domain}
                     onChange={e => setDomain(e.target.value)}
                     required
                  />
               </div>

               <div style={{ display: 'flex', gap: 16, flex: 1, minWidth: 200 }}>
                  <input
                     type="number"
                     className="form-input"
                     style={{ background: 'var(--bg-elevated)', width: 100 }}
                     placeholder="Max Assets"
                     value={maxAssets}
                     onChange={e => setMaxAssets(parseInt(e.target.value, 10))}
                     min={1}
                     max={500}
                  />

                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                     <input
                        type="checkbox"
                        checked={skipDiscovery}
                        onChange={e => setSkipDiscovery(e.target.checked)}
                     />
                     Skip Discovery
                  </label>
               </div>

               <button type="submit" className="btn btn-primary btn-lg" disabled={triggerScan.isPending}>
                  {triggerScan.isPending ? <Loader2 size={18} className="spinner" /> : <Play size={18} />}
                  Start Scan
               </button>
            </form>

            {activeStatus && activeStatus.status !== 'completed' && activeStatus.status !== 'failed' && (
               <div style={{ marginTop: 24, padding: 20, background: 'rgba(11, 13, 20, 0.5)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                     <div style={{ fontWeight: 600, color: 'var(--pnb-gold)' }}>Scan in Progress...</div>
                     <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        {activeStatus.assets_scanned} / {activeStatus.assets_discovered} assets processed
                     </div>
                  </div>
                  <div className="progress-bar">
                     <div className="progress-fill" style={{ width: `${Math.min(100, (activeStatus.assets_scanned / Math.max(1, activeStatus.assets_discovered)) * 100)}%` }} />
                  </div>
                  <div style={{ marginTop: 12, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                     Scanning domain and evaluating cryptographic protocols against NIST standards.
                  </div>
               </div>
            )}
         </div>

         <div className="card">
            <div className="chart-title">Scan History</div>
            {isLoading ? <LoadingSpinner /> : (
               <div className="data-table-wrapper" style={{ border: 'none' }}>
                  <table className="data-table">
                     <thead>
                        <tr>
                           <th>Target Domain</th>
                           <th>Status</th>
                           <th>Total Discovered</th>
                           <th>Assets Processed</th>
                           <th>Started At</th>
                           <th>Completed At</th>
                           <th>Duration</th>
                        </tr>
                     </thead>
                     <tbody>
                        {scans?.items && scans.items.length > 0 ? (
                           scans.items.map(scan => {
                              let duration = '—';
                              if (scan.started_at && scan.completed_at) {
                                 const ms = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
                                 if (ms > 0) {
                                    const min = Math.floor(ms / 60000);
                                    const sec = Math.floor((ms % 60000) / 1000);
                                    duration = `${min}m ${sec}s`;
                                 }
                              }

                              return (
                                 <tr key={scan.id}>
                                    <td className="td-primary">{scan.domain}</td>
                                    <td>
                                       <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                          {scan.status === 'completed' && <CheckCircle2 size={14} color="var(--color-success)" />}
                                          {scan.status === 'failed' && <XCircle size={14} color="var(--color-danger)" />}
                                          {scan.status === 'running' && <Loader2 size={14} color="var(--color-info)" className="spinner" />}
                                          {scan.status === 'pending' && <Clock size={14} color="var(--text-muted)" />}
                                          <span className={`badge ${scan.status === 'completed' ? 'success' :
                                                scan.status === 'failed' ? 'danger' :
                                                   scan.status === 'running' ? 'info' : 'warning'
                                             }`}>
                                             {scan.status}
                                          </span>
                                       </div>
                                    </td>
                                    <td>{scan.assets_discovered}</td>
                                    <td>{scan.assets_scanned}</td>
                                    <td style={{ fontSize: '0.8rem' }}>
                                       {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                                    </td>
                                    <td style={{ fontSize: '0.8rem' }}>
                                       {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
                                    </td>
                                    <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{duration}</td>
                                 </tr>
                              );
                           })
                        ) : (
                           <tr>
                              <td colSpan={7}>
                                 <div className="empty-state">
                                    <Search size={32} />
                                    <p>No scans found. Trigger a new one above.</p>
                                 </div>
                              </td>
                           </tr>
                        )}
                     </tbody>
                  </table>
               </div>
            )}
         </div>

      </div>
   );
}

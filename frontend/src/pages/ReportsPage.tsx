import { useState } from 'react';
import { useReports, useGenerateReport, useScheduleReport } from '../hooks/useReports';
import { useScans } from '../hooks/useScans';
import { FileText, Calendar, Download, Loader2, Plus } from 'lucide-react';

export default function ReportsPage() {
   const [activeTab, setActiveTab] = useState<'generated' | 'generate' | 'schedule'>('generated');

   const { data: reports, isLoading: reportsLoading } = useReports();
   const { data: scans } = useScans(1, 100);

   const generateReport = useGenerateReport();
   const scheduleReport = useScheduleReport();

   // Generate form state
   const [genScanId, setGenScanId] = useState('');
   const [genType, setGenType] = useState('executive');
   const [genFormat, setGenFormat] = useState('pdf');

   // Schedule form state
   const [schType, setSchType] = useState('full');
   const [schFreq, setSchFreq] = useState('weekly');
   const [schEmail, setSchEmail] = useState('');

   const handleGenerate = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!genScanId) return;
      try {
         await generateReport.mutateAsync({
            scan_id: genScanId,
            report_type: genType,
            file_format: genFormat,
         });
         setActiveTab('generated');
      } catch (err) {
         console.error('Failed to generate report', err);
         // Still switch tab or show an error
         alert('Failed to generate report on the backend. See console for details.');
      }
   };

   const handleSchedule = async (e: React.FormEvent) => {
      e.preventDefault();
      await scheduleReport.mutateAsync({
         report_type: schType,
         frequency: schFreq,
         delivery_email: schEmail || undefined,
      });
      setActiveTab('generated');
   };

   return (
      <div className="animate-fadeIn">
         <div className="page-header">
            <h2>Reports</h2>
            <p>Generate on-demand compliance reports or schedule automated deliverables.</p>
         </div>

         <div className="tabs">
            <button className={`tab ${activeTab === 'generated' ? 'active' : ''}`} onClick={() => setActiveTab('generated')}>
               Generated <span className="tab-count">{reports?.total ?? 0}</span>
            </button>
            <button className={`tab ${activeTab === 'generate' ? 'active' : ''}`} onClick={() => setActiveTab('generate')}>
               New Report
            </button>
            <button className={`tab ${activeTab === 'schedule' ? 'active' : ''}`} onClick={() => setActiveTab('schedule')}>
               Schedule
            </button>
         </div>

         {activeTab === 'generated' && (
            <div className="card">
               <div className="chart-title mb-md">Available Reports</div>
               {reportsLoading ? (
                  <div className="loading-spinner"><div className="spinner" /></div>
               ) : reports?.items && reports.items.length > 0 ? (
                  <div className="data-table-wrapper" style={{ border: 'none' }}>
                     <table className="data-table">
                        <thead>
                           <tr>
                              <th>Type</th>
                              <th>Format</th>
                              <th>File Path</th>
                              <th>Generated At</th>
                              <th>Expires</th>
                              <th>Action</th>
                           </tr>
                        </thead>
                        <tbody>
                           {reports.items.map(r => (
                              <tr key={r.id}>
                                 <td className="td-primary" style={{ textTransform: 'capitalize' }}>{r.report_type}</td>
                                 <td style={{ textTransform: 'uppercase' }}>{r.file_format}</td>
                                 <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{r.file_path}</td>
                                 <td>{new Date(r.generated_at).toLocaleString()}</td>
                                 <td>{new Date(r.expires_at).toLocaleDateString()}</td>
                                 <td>
                                    <button
                                       className="btn btn-outline btn-sm"
                                       onClick={() => alert(`Downloading report: ${r.file_path}\nThis will be exported as a ${r.file_format.toUpperCase()} document.`)}
                                    >
                                       <Download size={14} /> Download
                                    </button>
                                 </td>
                              </tr>
                           ))}
                        </tbody>
                     </table>
                  </div>
               ) : (
                  <div className="empty-state">
                     <FileText size={48} />
                     <h3>No Reports Generated</h3>
                     <p>Use the "New Report" tab to create your first report.</p>
                     <button className="btn btn-primary mt-lg" onClick={() => setActiveTab('generate')}>
                        Generate Report
                     </button>
                  </div>
               )}
            </div>
         )}

         {activeTab === 'generate' && (
            <div className="card" style={{ maxWidth: 600 }}>
               <div className="chart-title mb-md">Generate On-Demand Report</div>
               <form onSubmit={handleGenerate}>
                  <div className="form-group">
                     <label className="form-label">Select Scan</label>
                     <select
                        className="form-select"
                        value={genScanId}
                        onChange={e => setGenScanId(e.target.value)}
                        required
                     >
                        <option value="">-- Choose a completed scan --</option>
                        {scans?.items?.filter(s => s.status === 'completed').map(s => (
                           <option key={s.id} value={s.id}>
                              {s.domain} ({new Date(s.completed_at!).toLocaleDateString()})
                           </option>
                        ))}
                     </select>
                  </div>

                  <div className="form-group">
                     <label className="form-label">Report Type</label>
                     <select className="form-select" value={genType} onChange={e => setGenType(e.target.value)}>
                        <option value="executive">Executive Summary</option>
                        <option value="technical">Technical Details</option>
                        <option value="compliance">Compliance (FIPS/CERT-In)</option>
                        <option value="full">Full Assessment</option>
                     </select>
                  </div>

                  <div className="form-group">
                     <label className="form-label">File Format</label>
                     <select className="form-select" value={genFormat} onChange={e => setGenFormat(e.target.value)}>
                        <option value="pdf">PDF Document</option>
                        <option value="csv">CSV Spreadsheet</option>
                        <option value="json">JSON Raw Data</option>
                     </select>
                  </div>

                  <div className="mt-lg pt-lg" style={{ borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                     <button type="button" className="btn btn-ghost" onClick={() => setActiveTab('generated')}>Cancel</button>
                     <button type="submit" className="btn btn-primary" disabled={generateReport.isPending || !genScanId}>
                        {generateReport.isPending ? <Loader2 size={16} className="spinner" /> : <Plus size={16} />}
                        Generate Now
                     </button>
                  </div>
               </form>
            </div>
         )}

         {activeTab === 'schedule' && (
            <div className="card" style={{ maxWidth: 600 }}>
               <div className="chart-title mb-md">Schedule Automated Reports</div>
               <form onSubmit={handleSchedule}>
                  <div className="form-group">
                     <label className="form-label">Report Type</label>
                     <select className="form-select" value={schType} onChange={e => setSchType(e.target.value)}>
                        <option value="executive">Executive Summary</option>
                        <option value="technical">Technical Details</option>
                        <option value="compliance">Compliance (FIPS/CERT-In)</option>
                        <option value="full">Full Assessment</option>
                     </select>
                  </div>

                  <div className="form-group">
                     <label className="form-label">Frequency</label>
                     <select className="form-select" value={schFreq} onChange={e => setSchFreq(e.target.value)}>
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                        <option value="quarterly">Quarterly</option>
                     </select>
                  </div>

                  <div className="form-group">
                     <label className="form-label">Delivery Email (Optional)</label>
                     <input
                        type="email"
                        className="form-input"
                        placeholder="ciso@pnb.bank.in"
                        value={schEmail}
                        onChange={e => setSchEmail(e.target.value)}
                     />
                     <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>
                        Reports will be emailed directly to this address when generated.
                     </div>
                  </div>

                  <div className="mt-lg pt-lg" style={{ borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                     <button type="button" className="btn btn-ghost" onClick={() => setActiveTab('generated')}>Cancel</button>
                     <button type="submit" className="btn btn-gold" disabled={scheduleReport.isPending}>
                        {scheduleReport.isPending ? <Loader2 size={16} className="spinner" /> : <Calendar size={16} />}
                        Save Schedule
                     </button>
                  </div>
               </form>
            </div>
         )}
      </div>
   );
}

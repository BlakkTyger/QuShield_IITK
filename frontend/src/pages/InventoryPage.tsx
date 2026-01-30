import { useState } from 'react';
import { useAssets, useAssetDetail } from '../hooks/useAssets';
import LoadingSpinner from '../components/LoadingSpinner';
import { Search, X, ChevronLeft, ChevronRight, Server } from 'lucide-react';

export default function InventoryPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [safetyFilter, setSafetyFilter] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);

  const { data, isLoading } = useAssets({
    page,
    size: 20,
    search: search || undefined,
    risk_level: riskFilter || undefined,
    quantum_safety: safetyFilter || undefined,
  });

  const { data: detail } = useAssetDetail(selectedAsset);

  const totalPages = data ? Math.ceil(data.total / 20) : 0;

  return (
    <div className="animate-fadeIn">
      <div className="page-header">
        <h2>Asset Inventory</h2>
        <p>Comprehensive view of all discovered assets and their security posture</p>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <div className="search-bar" style={{ flex: 1, maxWidth: 400 }}>
          <Search size={16} />
          <input
            placeholder="Search by FQDN or IP..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        {['critical', 'high', 'medium', 'low'].map((level) => (
          <button
            key={level}
            className={`filter-chip ${riskFilter === level ? 'active' : ''}`}
            onClick={() => { setRiskFilter(riskFilter === level ? '' : level); setPage(1); }}
          >
            {level}
          </button>
        ))}

        {['FULLY_SAFE', 'HYBRID', 'VULNERABLE', 'CRITICAL'].map((safety) => (
          <button
            key={safety}
            className={`filter-chip ${safetyFilter === safety ? 'active' : ''}`}
            onClick={() => { setSafetyFilter(safetyFilter === safety ? '' : safety); setPage(1); }}
          >
            {safety.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Table */}
      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>FQDN</th>
                  <th>Port</th>
                  <th>IP Address</th>
                  <th>Type</th>
                  <th>Risk Level</th>
                  <th>Quantum Safety</th>
                  <th>HNDL Score</th>
                  <th>Cert Tier</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {data?.items && data.items.length > 0  ? (
                  data.items.map((asset) => (
                    <tr
                      key={asset.id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSelectedAsset(asset.id)}
                    >
                      <td className="td-primary">{asset.fqdn}</td>
                      <td>{asset.port}</td>
                      <td>{asset.ipv4_address || '—'}</td>
                      <td>{asset.asset_type || '—'}</td>
                      <td>
                        <span className={`badge ${asset.risk_level || 'info'}`}>
                          {asset.risk_level || 'unknown'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${
                          asset.quantum_safety === 'FULLY_SAFE' ? 'quantum-safe' :
                          asset.quantum_safety === 'HYBRID' ? 'hybrid' :
                          asset.quantum_safety === 'CRITICAL' ? 'critical' : 'vulnerable'
                        }`}>
                          {asset.quantum_safety || 'Unknown'}
                        </span>
                      </td>
                      <td>{asset.hndl_score?.toFixed(2) ?? '—'}</td>
                      <td>
                        <span className={`badge ${
                          asset.cert_tier === 'PLATINUM' ? 'elite' :
                          asset.cert_tier === 'GOLD' ? 'gold' :
                          asset.cert_tier === 'SILVER' ? 'standard' : 'legacy'
                        }`}>
                          {asset.cert_tier || '—'}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.78rem' }}>{asset.discovery_source || '—'}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={9}>
                      <div className="empty-state">
                        <Server size={40} />
                        <h3>No Assets Found</h3>
                        <p>Run a scan to discover assets</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination">
              <div className="pagination-info">
                Showing {(page - 1) * 20 + 1}–{Math.min(page * 20, data?.total ?? 0)} of {data?.total ?? 0}
              </div>
              <div className="pagination-controls">
                <button
                  className="pagination-btn"
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1}
                >
                  <ChevronLeft size={14} />
                </button>
                {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => i + 1).map((p) => (
                  <button
                    key={p}
                    className={`pagination-btn ${page === p ? 'active' : ''}`}
                    onClick={() => setPage(p)}
                  >
                    {p}
                  </button>
                ))}
                <button
                  className="pagination-btn"
                  onClick={() => setPage(page + 1)}
                  disabled={page >= totalPages}
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Asset Detail Modal */}
      {selectedAsset && detail && (
        <div className="modal-overlay" onClick={() => setSelectedAsset(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{detail.fqdn}</h3>
              <button className="modal-close" onClick={() => setSelectedAsset(null)}>
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 20 }}>
              <div>
                <span className="form-label">IP Address</span>
                <div style={{ color: 'var(--text-primary)' }}>{detail.ipv4_address || '—'}</div>
              </div>
              <div>
                <span className="form-label">Port</span>
                <div style={{ color: 'var(--text-primary)' }}>{detail.port}</div>
              </div>
              <div>
                <span className="form-label">Risk Level</span>
                <span className={`badge ${detail.risk_level || 'info'}`}>{detail.risk_level || 'unknown'}</span>
              </div>
              <div>
                <span className="form-label">Quantum Safety</span>
                <span className={`badge ${
                  detail.quantum_safety === 'FULLY_SAFE' ? 'quantum-safe' :
                  detail.quantum_safety === 'HYBRID' ? 'hybrid' :
                  detail.quantum_safety === 'CRITICAL' ? 'critical' : 'vulnerable'
                }`}>{detail.quantum_safety || 'Unknown'}</span>
              </div>
              <div>
                <span className="form-label">HNDL Score</span>
                <div style={{ color: 'var(--pnb-gold)', fontWeight: 700 }}>{detail.hndl_score?.toFixed(3) ?? '—'}</div>
              </div>
              <div>
                <span className="form-label">Recommended Action</span>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                  {detail.recommended_action || 'No action required'}
                </div>
              </div>
            </div>

            {/* Certificates */}
            {detail.certificates && detail.certificates.length > 0 && (
              <>
                <div className="chart-title" style={{ marginBottom: 12 }}>SSL/TLS Certificates</div>
                <div className="data-table-wrapper" style={{ marginBottom: 16 }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Subject CN</th>
                        <th>Issuer</th>
                        <th>CA</th>
                        <th>Valid Until</th>
                        <th>Days Left</th>
                        <th>Key</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.certificates.map((cert) => (
                        <tr key={cert.id}>
                          <td className="td-primary">{cert.subject_cn || '—'}</td>
                          <td>{cert.issuer_cn || '—'}</td>
                          <td>{cert.certificate_authority || '—'}</td>
                          <td>{cert.valid_until ? new Date(cert.valid_until).toLocaleDateString() : '—'}</td>
                          <td>
                            <span className={`badge ${
                              (cert.days_until_expiry ?? 0) <= 30 ? 'danger' :
                              (cert.days_until_expiry ?? 0) <= 90 ? 'warning' : 'success'
                            }`}>
                              {cert.days_until_expiry ?? '—'}d
                            </span>
                          </td>
                          <td>{cert.key_algorithm} {cert.key_size}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {/* Crypto Details */}
            {detail.crypto_security && detail.crypto_security.length > 0 && (
              <>
                <div className="chart-title" style={{ marginBottom: 12 }}>Crypto Security</div>
                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>TLS Version</th>
                        <th>Cipher Suite</th>
                        <th>Key Exchange</th>
                        <th>Key Length</th>
                        <th>PFS</th>
                        <th>PQC</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.crypto_security.map((cs) => (
                        <tr key={cs.id}>
                          <td className="td-primary">{cs.tls_version || '—'}</td>
                          <td style={{ fontSize: '0.78rem' }}>{cs.cipher_suite || '—'}</td>
                          <td>{cs.key_exchange_algorithm || '—'}</td>
                          <td>{cs.key_length || '—'}</td>
                          <td>
                            <span className={`badge ${cs.forward_secrecy ? 'success' : 'danger'}`}>
                              {cs.forward_secrecy ? 'Yes' : 'No'}
                            </span>
                          </td>
                          <td>{cs.pqc_algorithm || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

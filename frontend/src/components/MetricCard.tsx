import type { ReactNode } from 'react';

interface MetricCardProps {
  icon: ReactNode;
  label: string;
  value: string | number;
  variant?: 'gold' | 'maroon' | 'success' | 'danger' | 'warning' | 'info';
  subtitle?: string;
}

export default function MetricCard({ icon, label, value, variant = 'gold', subtitle }: MetricCardProps) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${variant}`}>
        {icon}
      </div>
      <div className="metric-content">
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        {subtitle && <div className="metric-change">{subtitle}</div>}
      </div>
    </div>
  );
}

import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { DashboardMetrics, RiskDistribution } from '../types/api';

export function useDashboardMetrics(scanId?: string) {
  return useQuery({
    queryKey: ['dashboard-metrics', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<DashboardMetrics>(`/dashboard/metrics${params}`);
      return data;
    },
  });
}

export function useRiskDistribution(scanId?: string) {
  return useQuery({
    queryKey: ['risk-distribution', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<RiskDistribution>(`/dashboard/risk-distribution${params}`);
      return data;
    },
  });
}

import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { CBOMMetrics } from '../types/api';

export function useCBOMMetrics(scanId?: string) {
  return useQuery({
    queryKey: ['cbom-metrics', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<CBOMMetrics>(`/cbom/metrics${params}`);
      return data;
    },
  });
}

export function useExportCBOM() {
  const exportCBOM = async (scanId?: string) => {
    const params = scanId ? `?scan_id=${scanId}` : '';
    const { data } = await api.get(`/cbom/export${params}`);
    // Trigger download
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return { exportCBOM };
}

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../lib/api';
import type { ScanListResponse, ScanResponse, ScanStatus, ScanTrigger } from '../types/api';

export function useScans(page = 1, size = 20) {
  return useQuery({
    queryKey: ['scans', page],
    queryFn: async () => {
      const { data } = await api.get<ScanListResponse>(`/scans?page=${page}&size=${size}`);
      return data;
    },
  });
}

export function useTriggerScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanData: ScanTrigger) => {
      const { data } = await api.post<ScanResponse>('/scans/trigger', scanData);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useScanStatus(scanId: string | null) {
  return useQuery({
    queryKey: ['scan-status', scanId],
    queryFn: async () => {
      if (!scanId) return null;
      const { data } = await api.get<ScanStatus>(`/scans/${scanId}/status`);
      return data;
    },
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      return data.status === 'completed' || data.status === 'failed' ? false : 5000;
    },
  });
}

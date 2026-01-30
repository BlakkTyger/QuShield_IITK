import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { PostureSummary, RecommendationList, PQCCertificateList } from '../types/api';

export function usePostureSummary(scanId?: string) {
  return useQuery({
    queryKey: ['posture-summary', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<PostureSummary>(`/posture/summary${params}`);
      return data;
    },
  });
}

export function useRecommendations(scanId?: string) {
  return useQuery({
    queryKey: ['posture-recommendations', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<RecommendationList>(`/posture/recommendations${params}`);
      return data;
    },
  });
}

export function usePQCCertificates(scanId?: string, page = 1, size = 20) {
  return useQuery({
    queryKey: ['posture-certificates', scanId, page],
    queryFn: async () => {
      const params = new URLSearchParams({ page: String(page), size: String(size) });
      if (scanId) params.append('scan_id', scanId);
      const { data } = await api.get<PQCCertificateList>(`/posture/certificates?${params}`);
      return data;
    },
  });
}

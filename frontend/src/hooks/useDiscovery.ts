import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { DiscoverySummary, DomainList, GraphData } from '../types/api';

export function useDiscoverySummary(scanId?: string) {
  return useQuery({
    queryKey: ['discovery-summary', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<DiscoverySummary>(`/discovery/summary${params}`);
      return data;
    },
  });
}

export function useDiscoveryDomains(scanId?: string, page = 1, size = 50) {
  return useQuery({
    queryKey: ['discovery-domains', scanId, page, size],
    queryFn: async () => {
      const params = new URLSearchParams({ page: String(page), size: String(size) });
      if (scanId) params.append('scan_id', scanId);
      const { data } = await api.get<DomainList>(`/discovery/domains?${params}`);
      return data;
    },
  });
}

export function useDiscoveryGraph(scanId?: string) {
  return useQuery({
    queryKey: ['discovery-graph', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<GraphData>(`/discovery/graph${params}`);
      return data;
    },
  });
}

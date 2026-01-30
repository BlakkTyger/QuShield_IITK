import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { EnterpriseRating, AssetRating } from '../types/api';

export function useEnterpriseRating(scanId?: string) {
  return useQuery({
    queryKey: ['enterprise-rating', scanId],
    queryFn: async () => {
      const params = scanId ? `?scan_id=${scanId}` : '';
      const { data } = await api.get<EnterpriseRating>(`/rating/enterprise${params}`);
      return data;
    },
  });
}

export function useAssetRatings(scanId?: string, page = 1, size = 20) {
  return useQuery({
    queryKey: ['asset-ratings', scanId, page],
    queryFn: async () => {
      const params = new URLSearchParams({ page: String(page), size: String(size) });
      if (scanId) params.append('scan_id', scanId);
      const { data } = await api.get<AssetRating>(`/rating/assets?${params}`);
      return data;
    },
  });
}

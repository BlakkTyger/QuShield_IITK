import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import type { AssetListResponse, AssetDetail } from '../types/api';

interface AssetFilters {
  page?: number;
  size?: number;
  risk_level?: string;
  quantum_safety?: string;
  asset_type?: string;
  scan_id?: string;
  search?: string;
}

export function useAssets(filters: AssetFilters = {}) {
  return useQuery({
    queryKey: ['assets', filters],
    queryFn: async () => {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== '') params.append(key, String(value));
      });
      const { data } = await api.get<AssetListResponse>(`/assets?${params}`);
      return data;
    },
  });
}

export function useAssetDetail(assetId: string | null) {
  return useQuery({
    queryKey: ['asset-detail', assetId],
    queryFn: async () => {
      if (!assetId) return null;
      const { data } = await api.get<AssetDetail>(`/assets/${assetId}`);
      return data;
    },
    enabled: !!assetId,
  });
}

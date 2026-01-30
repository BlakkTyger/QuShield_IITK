import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../lib/api';
import type { ReportListResponse, ReportResponse, ScheduledReportResponse } from '../types/api';

export function useReports(page = 1, size = 20) {
  return useQuery({
    queryKey: ['reports', page],
    queryFn: async () => {
      const { data } = await api.get<ReportListResponse>(`/reports?page=${page}&size=${size}`);
      return data;
    },
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (reportData: { scan_id: string; report_type: string; file_format: string }) => {
      const { data } = await api.post<ReportResponse>('/reports/generate', reportData);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
  });
}

export function useScheduleReport() {
  return useMutation({
    mutationFn: async (scheduleData: {
      report_type: string;
      frequency: string;
      cron_expression?: string;
      delivery_email?: string;
    }) => {
      const { data } = await api.post<ScheduledReportResponse>('/reports/schedule', scheduleData);
      return data;
    },
  });
}

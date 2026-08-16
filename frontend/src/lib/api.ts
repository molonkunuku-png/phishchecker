import axios from 'axios';
import type { ScanResult, HistoryResponse, BulkResponse } from './types';

export const base = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
});

export async function fetchHistory(): Promise<HistoryResponse> {
  const { data } = await base.get('/api/v2/scans/history');
  return data;
}

export async function submitScan(url: string, mode = 'standard'): Promise<ScanResult> {
  const { data } = await base.post('/api/v2/scans', { url, mode });
  return data;
}

export async function submitBulk(urls: string[], mode = 'quick'): Promise<BulkResponse> {
  const { data } = await base.post('/scan/bulk', { urls, mode });
  return data;
}

export async function fetchScanDetail(id: string): Promise<ScanResult> {
  const { data } = await base.get(`/api/v2/scans/${encodeURIComponent(id)}`);
  return data;
}

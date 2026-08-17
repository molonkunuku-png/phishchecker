import axios from 'axios';
import type { ScanResult, HistoryResponse, BulkResponse } from './types';

export const base = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
});

export async function getCsrf(): Promise<string> {
  const { data } = await base.get('/api/csrf');
  return data?.csrf_token || '';
}

export async function fetchHistory(): Promise<HistoryResponse> {
  const { data } = await base.get('/api/v2/scans/history');
  return data;
}

export async function submitScan(url: string, mode = 'standard'): Promise<ScanResult> {
  const token = await getCsrf();
  const { data } = await base.post('/api/v2/scans', { url, mode }, {
    headers: { 'X-CSRF-Token': token },
  });
  return data;
}

export async function submitBulk(urls: string[], mode = 'quick'): Promise<BulkResponse> {
  const token = await getCsrf();
  const { data } = await base.post('/scan/bulk', { urls, mode }, {
    headers: { 'X-CSRF-Token': token },
  });
  return data;
}

export async function fetchScanDetail(id: string): Promise<ScanResult> {
  const token = await getCsrf();
  const { data } = await base.get(`/api/v2/scans/${encodeURIComponent(id)}`, {
    headers: { 'X-CSRF-Token': token },
  });
  return data;
}

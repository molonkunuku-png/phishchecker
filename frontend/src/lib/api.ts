import axios from 'axios';
import type { ScanResult, HistoryResponse, BulkResponse, StatusResponse } from './types';

export const base = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
});

export async function getStatus(): Promise<StatusResponse> {
  const { data } = await base.get('/api/v2/status');
  return data;
}

export async function getCsrf(): Promise<string> {
  const { data } = await base.get('/api/csrf');
  return data?.csrf_token || '';
}

export async function fetchHistory(params?: { page?: number; page_size?: number; risk?: string; q?: string }): Promise<HistoryResponse> {
  const { data } = await base.get('/api/v2/scans/history', { params });
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

export async function downloadExport(fmt: 'json' | 'csv' = 'json'): Promise<void> {
  const token = await getCsrf();
  const res = await base.get(`/api/v2/scans/export?format=${encodeURIComponent(fmt)}`, {
    headers: { 'X-CSRF-Token': token },
    responseType: 'blob',
  });
  const url = window.URL.createObjectURL(new Blob([res.data]));
  const a = document.createElement('a');
  a.href = url;
  a.download = `phishchecker-export.${fmt}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
}

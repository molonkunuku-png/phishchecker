export type ScanResult = {
  id?: string;
  url: string;
  domain?: string;
  risk?: string;
  score?: number;
  reasons?: string[];
  details?: Record<string, unknown>;
  mode?: string;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  threat_intel?: { hits?: number; summary?: string; details?: string[] };
};

export type HistoryItem = {
  id: string;
  url: string;
  domain: string;
  risk: string;
  score: number;
  mode: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  reasons: string[];
};

export type HistoryResponse = {
  items: HistoryItem[];
  count: number;
  page: number;
  page_size: number;
};

export type BulkResponse = {
  results: ScanResult[];
};

export type StatusResponse = {
  service: string;
  version: string;
  features: Record<string, boolean>;
};

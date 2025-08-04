// API client for MCP-SEC Web API
import { Drift, DriftDiff } from '@/types/drift';
import { mockDrifts, mockDriftDiff } from './mockData';

const API_BASE_URL = 'http://localhost:8000/api';

export interface ApprovalRequest {
  request_id: string;
  notification_id: string;
  server_name: string;
  change_type: string;
  change_summary: string;
  risk_level: string;
  created_at: string;
  expires_at: string;
  status: string;
  approved_by?: string;
  approved_at?: string;
  rejection_reason?: string;
}

export interface ApprovalAction {
  action: 'approve' | 'reject';
  approved_by: string;
  reason?: string;
}

export interface DashboardStats {
  pending_drifts: number;
  total_drifts: number;
  pending_approvals: number;
  approved_count: number;
  servers_count: number;
  approval_rate: number;
}

class ApiClient {
  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    
    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
        ...options,
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API request failed: ${url}`, error);
      throw error;
    }
  }

  // Drift endpoints
  async getDrifts(limit = 100, skip = 0, status?: string): Promise<Drift[]> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      skip: skip.toString(),
    });
    
    if (status) {
      params.append('status', status);
    }

    return this.request<Drift[]>(`/drifts?${params}`);
  }

  async getDrift(driftId: string): Promise<Drift> {
    return this.request<Drift>(`/drifts/${driftId}`);
  }

  async getDriftDiff(driftId: string): Promise<DriftDiff & { vulnerability?: any }> {
    return this.request<DriftDiff & { vulnerability?: any }>(`/drifts/${driftId}/diff`);
  }

  async approveDrift(driftId: string, approvedBy: string): Promise<{ message: string; drift_id: string }> {
    return this.request(`/drifts/${driftId}/approve`, {
      method: 'POST',
      body: JSON.stringify({
        action: 'approve',
        approved_by: approvedBy,
      }),
    });
  }

  // Approval endpoints
  async getApprovalRequests(status = 'pending'): Promise<ApprovalRequest[]> {
    return this.request<ApprovalRequest[]>(`/approvals?status=${status}`);
  }

  async processApproval(requestId: string, action: ApprovalAction): Promise<{ message: string; request_id: string }> {
    return this.request(`/approvals/${requestId}/action`, {
      method: 'POST',
      body: JSON.stringify(action),
    });
  }

  // Stats endpoint
  async getStats(): Promise<DashboardStats> {
    return this.request<DashboardStats>('/stats');
  }

  // Health check
  async healthCheck(): Promise<{ message: string; status: string }> {
    return fetch(`${API_BASE_URL.replace('/api', '')}`)
      .then(res => res.json())
      .catch(() => ({ message: 'API not available', status: 'error' }));
  }
}

export const apiClient = new ApiClient();

// React Query hooks for easier data fetching
export const useApiHealth = () => {
  return apiClient.healthCheck();
};


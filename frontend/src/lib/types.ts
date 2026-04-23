export interface Profile {
  id: string
  email: string
  full_name: string
  avatar_url: string
  created_at: string
  updated_at: string
}

export interface Scan {
  id: string
  user_id: string
  repo_url: string
  branch: string
  name: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  depth: 'quick' | 'standard' | 'thorough'
  severity_threshold: string
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  duration_seconds: number
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface Finding {
  id: string
  scan_id: string
  user_id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  file_path: string
  line_number: number
  verdict: 'confirmed' | 'likely' | 'inconclusive' | 'not_exploitable'
  evidence: string
  remediation: string
  cwe_id: string
  created_at: string
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'

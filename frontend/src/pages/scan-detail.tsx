import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ArrowLeft,
  GitBranch,
  Clock,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { StatusBadge } from '@/components/status-badge'
import { SeverityBadge } from '@/components/severity-badge'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import type { Scan, Finding, SeverityLevel } from '@/lib/types'

function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return s > 0 ? `${m}m ${s}s` : `${m}m`
}

const verdictStyles: Record<string, string> = {
  confirmed: 'bg-red-500/10 text-red-700 border-red-500/20',
  likely: 'bg-orange-500/10 text-orange-700 border-orange-500/20',
  inconclusive: 'bg-slate-500/10 text-slate-600 border-slate-500/20',
  not_exploitable: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20',
}

function FindingRow({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border-b last:border-b-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-4 px-5 py-4 text-left hover:bg-muted/30 transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">{finding.title}</span>
            <SeverityBadge severity={finding.severity} />
            <Badge
              variant="outline"
              className={cn('text-xs capitalize', verdictStyles[finding.verdict])}
            >
              {finding.verdict.replace('_', ' ')}
            </Badge>
          </div>
          <div className="flex items-center gap-3 mt-1.5 text-xs text-muted-foreground">
            <span className="flex items-center gap-1 font-mono">
              <FileCode className="h-3 w-3" />
              {finding.file_path}{finding.line_number > 0 ? `:${finding.line_number}` : ''}
            </span>
            {finding.cwe_id && (
              <span>{finding.cwe_id}</span>
            )}
            <span className="capitalize">{finding.category.replace('_', ' ')}</span>
          </div>
        </div>
        {expanded
          ? <ChevronUp className="h-4 w-4 mt-1 text-muted-foreground shrink-0" />
          : <ChevronDown className="h-4 w-4 mt-1 text-muted-foreground shrink-0" />}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-4">
              <Separator />
              {finding.description && (
                <div>
                  <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                    Description
                  </h4>
                  <p className="text-sm leading-relaxed">{finding.description}</p>
                </div>
              )}
              {finding.evidence && (
                <div>
                  <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                    Evidence
                  </h4>
                  <pre className="text-xs bg-muted/50 rounded-lg p-3 overflow-x-auto font-mono leading-relaxed">
                    {finding.evidence}
                  </pre>
                </div>
              )}
              {finding.remediation && (
                <div>
                  <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                    Remediation
                  </h4>
                  <p className="text-sm leading-relaxed">{finding.remediation}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('all')

  useEffect(() => {
    async function load() {
      if (!id) return
      const [scanRes, findingsRes] = await Promise.all([
        supabase.from('scans').select('*').eq('id', id).maybeSingle(),
        supabase.from('findings').select('*').eq('scan_id', id).order('severity'),
      ])
      setScan(scanRes.data)
      setFindings(findingsRes.data ?? [])
      setLoading(false)
    }
    load()
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-foreground/20 border-t-foreground" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="text-center py-24">
        <p className="text-lg font-medium">Scan not found</p>
        <Button variant="outline" className="mt-4" render={<Link to="/scans" />}>
          Back to Scans
        </Button>
      </div>
    )
  }

  const severityCounts: Record<SeverityLevel, number> = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  }

  const filteredFindings = activeTab === 'all'
    ? findings
    : findings.filter(f => f.severity === activeTab)

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <Button variant="ghost" size="sm" className="mb-4 -ml-2" render={<Link to="/scans" />}>
          <ArrowLeft className="mr-1.5 h-3.5 w-3.5" />
          Back to Scans
        </Button>

        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight">
                {scan.name || scan.repo_url}
              </h1>
              <StatusBadge status={scan.status} />
            </div>
            <div className="flex flex-wrap items-center gap-3 mt-2 text-sm text-muted-foreground">
              {scan.repo_url && (
                <a
                  href={scan.repo_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 hover:text-foreground transition-colors"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  {scan.repo_url.replace(/^https?:\/\//, '').replace(/\.git$/, '')}
                </a>
              )}
              <span className="flex items-center gap-1">
                <GitBranch className="h-3.5 w-3.5" />
                {scan.branch}
              </span>
              <Badge variant="secondary" className="capitalize">{scan.depth}</Badge>
              {scan.duration_seconds > 0 && (
                <span className="flex items-center gap-1">
                  <Clock className="h-3.5 w-3.5" />
                  {formatDuration(scan.duration_seconds)}
                </span>
              )}
              <span>{new Date(scan.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="grid grid-cols-2 sm:grid-cols-5 gap-3"
      >
        {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map((severity) => (
          <Card key={severity} className={cn(
            'cursor-pointer transition-all',
            activeTab === severity ? 'ring-2 ring-ring' : 'hover:bg-muted/50'
          )}
            onClick={() => setActiveTab(activeTab === severity ? 'all' : severity)}
          >
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-semibold">{severityCounts[severity]}</p>
              <p className="text-xs text-muted-foreground capitalize mt-0.5">{severity}</p>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.15 }}
      >
        <Card>
          <CardHeader className="pb-0">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                Findings
                <Badge variant="secondary" className="ml-1">
                  {filteredFindings.length}
                </Badge>
              </CardTitle>
              {activeTab !== 'all' && (
                <Button variant="ghost" size="sm" onClick={() => setActiveTab('all')}>
                  Clear filter
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0 mt-4">
            {filteredFindings.length === 0 ? (
              <div className="py-16 text-center">
                <ShieldCheck className="mx-auto h-10 w-10 text-muted-foreground/40 mb-3" />
                <p className="text-sm text-muted-foreground">
                  {findings.length === 0 ? 'No findings detected' : 'No findings match this filter'}
                </p>
              </div>
            ) : (
              filteredFindings.map((finding) => (
                <FindingRow key={finding.id} finding={finding} />
              ))
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Plus,
  ScanSearch,
  GitBranch,
  Clock,
  ChevronRight,
  Filter,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { StatusBadge } from '@/components/status-badge'
import { supabase } from '@/lib/supabase'
import type { Scan, ScanStatus } from '@/lib/types'

function formatDuration(seconds: number) {
  if (seconds < 60) return `${seconds}s`
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}

export function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  useEffect(() => {
    async function load() {
      const { data } = await supabase
        .from('scans')
        .select('*')
        .order('created_at', { ascending: false })
      setScans(data ?? [])
      setLoading(false)
    }
    load()
  }, [])

  const filtered = scans.filter(scan => {
    const matchesSearch = search === '' ||
      scan.name.toLowerCase().includes(search.toLowerCase()) ||
      scan.repo_url.toLowerCase().includes(search.toLowerCase())
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter
    return matchesSearch && matchesStatus
  })

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scans</h1>
          <p className="text-muted-foreground mt-1">
            {scans.length} total scan{scans.length !== 1 ? 's' : ''}
          </p>
        </div>
        <Button render={<Link to="/scans/new" />}>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1 }}
        className="flex flex-col sm:flex-row gap-3"
      >
        <Input
          placeholder="Search by name or URL..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-10 sm:max-w-xs"
        />
        <Select value={statusFilter} onValueChange={(val) => setStatusFilter(val ?? 'all')}>
          <SelectTrigger className="h-10 w-full sm:w-40">
            <Filter className="h-3.5 w-3.5 mr-2 text-muted-foreground" />
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="queued">Queued</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
          </SelectContent>
        </Select>
      </motion.div>

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-foreground/20 border-t-foreground" />
        </div>
      ) : filtered.length === 0 ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-24"
        >
          <ScanSearch className="mx-auto h-12 w-12 text-muted-foreground/40 mb-4" />
          <p className="text-lg font-medium">
            {scans.length === 0 ? 'No scans yet' : 'No matching scans'}
          </p>
          <p className="text-sm text-muted-foreground mt-1">
            {scans.length === 0
              ? 'Start by running your first security audit'
              : 'Try adjusting your filters'}
          </p>
          {scans.length === 0 && (
            <Button className="mt-6" render={<Link to="/scans/new" />}>
              <Plus className="mr-2 h-4 w-4" />
              Run First Scan
            </Button>
          )}
        </motion.div>
      ) : (
        <div className="space-y-2">
          {filtered.map((scan, i) => (
            <motion.div
              key={scan.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: i * 0.03 }}
            >
              <Link to={`/scans/${scan.id}`}>
                <Card className="hover:bg-muted/30 transition-colors cursor-pointer group">
                  <CardContent className="flex items-center gap-4 p-4 sm:p-5">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
                      <ScanSearch className="h-5 w-5 text-muted-foreground" />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium truncate">
                          {scan.name || scan.repo_url}
                        </p>
                        <StatusBadge status={scan.status as ScanStatus} />
                      </div>
                      <div className="flex items-center gap-3 mt-1.5 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <GitBranch className="h-3 w-3" />
                          {scan.branch}
                        </span>
                        <span className="capitalize">{scan.depth}</span>
                        {scan.duration_seconds > 0 && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDuration(scan.duration_seconds)}
                          </span>
                        )}
                        <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>

                    <div className="hidden sm:flex items-center gap-6">
                      {scan.status === 'completed' && (
                        <div className="flex items-center gap-3 text-xs">
                          {scan.critical_count > 0 && (
                            <span className="text-red-600 font-medium">{scan.critical_count} critical</span>
                          )}
                          {scan.high_count > 0 && (
                            <span className="text-orange-600 font-medium">{scan.high_count} high</span>
                          )}
                          <span className="text-muted-foreground">
                            {scan.findings_count} total
                          </span>
                        </div>
                      )}
                      <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
                    </div>
                  </CardContent>
                </Card>
              </Link>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Clock,
  ArrowRight,
  Plus,
  GitBranch,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { StatCard } from '@/components/stat-card'
import { StatusBadge } from '@/components/status-badge'
import { SeverityBadge } from '@/components/severity-badge'
import { supabase } from '@/lib/supabase'
import { useAuth } from '@/lib/auth-context'
import type { Scan, Finding } from '@/lib/types'

export function DashboardPage() {
  const { user } = useAuth()
  const [scans, setScans] = useState<Scan[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      const [scansRes, findingsRes] = await Promise.all([
        supabase
          .from('scans')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(5),
        supabase
          .from('findings')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(10),
      ])
      setScans(scansRes.data ?? [])
      setFindings(findingsRes.data ?? [])
      setLoading(false)
    }
    load()
  }, [])

  const totalScans = scans.length
  const completedScans = scans.filter(s => s.status === 'completed').length
  const totalFindings = findings.length
  const criticalFindings = findings.filter(f => f.severity === 'critical').length

  const firstName = user?.user_metadata?.full_name?.split(' ')[0] || 'there'

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-foreground/20 border-t-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Hello, {firstName}
          </h1>
          <p className="text-muted-foreground mt-1">
            Here is your security overview
          </p>
        </div>
        <Button render={<Link to="/scans/new" />}>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </motion.div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Scans"
          value={totalScans}
          subtitle={`${completedScans} completed`}
          icon={ScanSearch}
          iconClassName="bg-sky-500/10 text-sky-600"
          delay={0}
        />
        <StatCard
          title="Findings"
          value={totalFindings}
          subtitle="Across all scans"
          icon={ShieldAlert}
          iconClassName="bg-amber-500/10 text-amber-600"
          delay={0.05}
        />
        <StatCard
          title="Critical Issues"
          value={criticalFindings}
          subtitle="Needs attention"
          icon={ShieldCheck}
          iconClassName="bg-red-500/10 text-red-600"
          delay={0.1}
        />
        <StatCard
          title="Avg. Duration"
          value={
            completedScans > 0
              ? `${Math.round(scans.filter(s => s.status === 'completed').reduce((a, s) => a + s.duration_seconds, 0) / completedScans / 60)}m`
              : '--'
          }
          subtitle="Per scan"
          icon={Clock}
          iconClassName="bg-emerald-500/10 text-emerald-600"
          delay={0.15}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="lg:col-span-3"
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <CardTitle className="text-base font-semibold">Recent Scans</CardTitle>
              <Button variant="ghost" size="sm" render={<Link to="/scans" />} className="text-muted-foreground">
                View all <ArrowRight className="ml-1 h-3.5 w-3.5" />
              </Button>
            </CardHeader>
            <CardContent className="p-0">
              {scans.length === 0 ? (
                <div className="px-6 py-12 text-center">
                  <ScanSearch className="mx-auto h-10 w-10 text-muted-foreground/50 mb-3" />
                  <p className="text-sm text-muted-foreground">No scans yet</p>
                  <Button size="sm" variant="outline" className="mt-4" render={<Link to="/scans/new" />}>
                    Run your first scan
                  </Button>
                </div>
              ) : (
                <div className="divide-y">
                  {scans.map((scan) => (
                    <Link
                      key={scan.id}
                      to={`/scans/${scan.id}`}
                      className="flex items-center gap-4 px-6 py-3.5 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {scan.name || scan.repo_url}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <GitBranch className="h-3 w-3 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground">{scan.branch}</span>
                          <span className="text-xs text-muted-foreground">
                            {new Date(scan.created_at).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      <StatusBadge status={scan.status} />
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.25, ease: [0.16, 1, 0.3, 1] }}
          className="lg:col-span-2"
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold">Latest Findings</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {findings.length === 0 ? (
                <div className="px-6 py-12 text-center">
                  <ShieldCheck className="mx-auto h-10 w-10 text-muted-foreground/50 mb-3" />
                  <p className="text-sm text-muted-foreground">No findings yet</p>
                </div>
              ) : (
                <div className="divide-y">
                  {findings.slice(0, 6).map((finding) => (
                    <div key={finding.id} className="px-6 py-3">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-medium leading-snug truncate">{finding.title}</p>
                        <SeverityBadge severity={finding.severity} />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 truncate font-mono">
                        {finding.file_path}{finding.line_number > 0 ? `:${finding.line_number}` : ''}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  )
}

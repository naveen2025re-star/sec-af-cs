import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { ScanStatus } from '@/lib/types'

const statusStyles: Record<ScanStatus, string> = {
  queued: 'bg-slate-500/10 text-slate-600 border-slate-500/20 dark:text-slate-400',
  running: 'bg-sky-500/10 text-sky-700 border-sky-500/20 dark:text-sky-400',
  completed: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20 dark:text-emerald-400',
  failed: 'bg-red-500/10 text-red-700 border-red-500/20 dark:text-red-400',
}

const statusDot: Record<ScanStatus, string> = {
  queued: 'bg-slate-500',
  running: 'bg-sky-500 animate-pulse',
  completed: 'bg-emerald-500',
  failed: 'bg-red-500',
}

export function StatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  return (
    <Badge variant="outline" className={cn('font-medium capitalize gap-1.5', statusStyles[status], className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', statusDot[status])} />
      {status}
    </Badge>
  )
}

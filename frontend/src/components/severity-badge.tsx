import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { SeverityLevel } from '@/lib/types'

const severityStyles: Record<SeverityLevel, string> = {
  critical: 'bg-red-500/10 text-red-700 border-red-500/20 dark:text-red-400',
  high: 'bg-orange-500/10 text-orange-700 border-orange-500/20 dark:text-orange-400',
  medium: 'bg-amber-500/10 text-amber-700 border-amber-500/20 dark:text-amber-400',
  low: 'bg-sky-500/10 text-sky-700 border-sky-500/20 dark:text-sky-400',
  info: 'bg-slate-500/10 text-slate-600 border-slate-500/20 dark:text-slate-400',
}

export function SeverityBadge({ severity, className }: { severity: SeverityLevel; className?: string }) {
  return (
    <Badge variant="outline" className={cn('font-medium capitalize', severityStyles[severity], className)}>
      {severity}
    </Badge>
  )
}

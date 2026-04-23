import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Zap, Shield, Search, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { supabase } from '@/lib/supabase'
import { useAuth } from '@/lib/auth-context'
import { cn } from '@/lib/utils'

const depthOptions = [
  {
    value: 'quick',
    label: 'Quick',
    description: '5 strategies, 2-5 min',
    icon: Zap,
    iconColor: 'text-amber-600',
  },
  {
    value: 'standard',
    label: 'Standard',
    description: '11 strategies, 15-80 min',
    icon: Shield,
    iconColor: 'text-sky-600',
  },
  {
    value: 'thorough',
    label: 'Thorough',
    description: 'Full coverage, 30-120 min',
    icon: Search,
    iconColor: 'text-emerald-600',
  },
]

export function NewScanPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [name, setName] = useState('')
  const [depth, setDepth] = useState('standard')
  const [severityThreshold, setSeverityThreshold] = useState('medium')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return
    setError('')
    setSubmitting(true)

    const { data, error: insertError } = await supabase.from('scans').insert({
      user_id: user.id,
      repo_url: repoUrl,
      branch,
      name: name || repoUrl.split('/').pop()?.replace('.git', '') || 'Untitled Scan',
      depth,
      severity_threshold: severityThreshold,
      status: 'queued',
    }).select().maybeSingle()

    if (insertError) {
      setError(insertError.message)
      setSubmitting(false)
      return
    }

    if (data) {
      navigate(`/scans/${data.id}`)
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <h1 className="text-2xl font-semibold tracking-tight">New Scan</h1>
        <p className="text-muted-foreground mt-1">
          Configure and run a security audit on your repository
        </p>
      </motion.div>

      <motion.form
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        onSubmit={handleSubmit}
        className="space-y-6"
      >
        <Card>
          <CardContent className="p-6 space-y-5">
            <div>
              <Label htmlFor="repoUrl" className="text-sm font-medium">Repository URL</Label>
              <Input
                id="repoUrl"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/org/repo"
                className="mt-1.5 h-11"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="branch" className="text-sm font-medium">Branch</Label>
                <Input
                  id="branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className="mt-1.5 h-11"
                />
              </div>
              <div>
                <Label htmlFor="name" className="text-sm font-medium">
                  Scan Name <span className="text-muted-foreground font-normal">(optional)</span>
                </Label>
                <Input
                  id="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="My Audit"
                  className="mt-1.5 h-11"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <div>
          <Label className="text-sm font-medium mb-3 block">Scan Depth</Label>
          <div className="grid grid-cols-3 gap-3">
            {depthOptions.map((option) => (
              <Card
                key={option.value}
                className={cn(
                  'cursor-pointer transition-all',
                  depth === option.value
                    ? 'ring-2 ring-ring bg-accent/50'
                    : 'hover:bg-muted/50'
                )}
                onClick={() => setDepth(option.value)}
              >
                <CardContent className="p-4">
                  <option.icon className={cn('h-5 w-5 mb-2', option.iconColor)} />
                  <p className="text-sm font-medium">{option.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{option.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        <Card>
          <CardContent className="p-6">
            <Label htmlFor="severity" className="text-sm font-medium">Minimum Severity</Label>
            <Select value={severityThreshold} onValueChange={(val) => setSeverityThreshold(val ?? 'medium')}>
              <SelectTrigger className="mt-1.5 h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical only</SelectItem>
                <SelectItem value="high">High and above</SelectItem>
                <SelectItem value="medium">Medium and above</SelectItem>
                <SelectItem value="low">Low and above</SelectItem>
                <SelectItem value="info">Everything</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground mt-2">
              Findings below this threshold will be excluded from results
            </p>
          </CardContent>
        </Card>

        {error && (
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-sm text-destructive"
          >
            {error}
          </motion.p>
        )}

        <div className="flex justify-end gap-3">
          <Button type="button" variant="outline" onClick={() => navigate('/scans')}>
            Cancel
          </Button>
          <Button type="submit" disabled={submitting || !repoUrl}>
            {submitting ? (
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground/30 border-t-primary-foreground" />
            ) : (
              <>
                Start Scan
                <ArrowRight className="ml-2 h-4 w-4" />
              </>
            )}
          </Button>
        </div>
      </motion.form>
    </div>
  )
}

import { useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { Button, Card, CardContent, Input, Label } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { PortalShell } from '../components/PortalShell';
import { BREACH_TYPES } from '../constants/portalContent';

const TYPE_LABELS: Record<string, string> = {
  unauthorized_phi_access: 'Unauthorized PHI access',
  ransomware: 'Ransomware',
  employee_error: 'Employee error',
  vendor_breach: 'Vendor breach',
  lost_device: 'Lost device',
  other: 'Other',
};

export function BreachWorkflowPage() {
  const [breachType, setBreachType] = useState<string>(BREACH_TYPES[0]);
  const [affected, setAffected] = useState('');
  const [description, setDescription] = useState('');

  return (
    <PortalShell
      title="Breach Notification Workflow"
      description="HIPAA requires notifying affected individuals within 60 days of breach discovery."
    >
      <Card dense>
        <CardContent className="space-y-5 px-6 py-6">
          <div className="rounded-[10px] border border-warning/30 bg-warning/[0.07] px-4 py-3 text-[13px] text-warning">
            This will: revoke all active sessions, create breach record, start the 60-day
            notification clock, and alert the compliance team.
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="breachType">Breach Type</Label>
            <select
              id="breachType"
              value={breachType}
              onChange={(e) => setBreachType(e.target.value)}
              className={cn(
                'w-full rounded-[10px] border border-white/[0.12] bg-surface-raised px-3.5 py-[11px] text-[14px] text-foreground outline-none focus:border-primary',
              )}
            >
              {BREACH_TYPES.map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="affected">Estimated Affected Count</Label>
            <Input
              id="affected"
              type="number"
              min={0}
              value={affected}
              onChange={(e) => setAffected(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="desc">Description</Label>
            <textarea
              id="desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
              className="w-full resize-y rounded-[10px] border border-white/[0.12] bg-surface-raised px-3.5 py-2.5 text-[14px] text-foreground outline-none placeholder:text-faint focus:border-primary"
            />
          </div>

          <div className="rounded-[10px] border border-destructive/30 bg-destructive/[0.07] px-4 py-3 text-[13px] text-destructive">
            ⚠️ This action is irreversible and will be permanently logged. Only initiate
            for confirmed breaches.
          </div>

          <Button
            variant="destructive"
            onClick={() => toast.error('Breach workflow — confirm + backend pending')}
          >
            <AlertTriangle className="h-4 w-4" /> 🚨 Initiate Breach Workflow
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

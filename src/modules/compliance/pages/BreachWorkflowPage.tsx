import { useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import {
  Button,
  Card,
  CardContent,
  Input,
  Label,
  Select,
  Textarea,
} from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';
import { BREACH_TYPES, TYPE_LABELS } from '../constants/portalContent';
import { useBreachWorkflow } from '../hooks/useBreachWorkflow';

export function BreachWorkflowPage() {
  const { onInitiate } = useBreachWorkflow();
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
          <div className="rounded-md border border-warning/30 bg-warning/[0.07] px-4 py-3 text-[13px] text-warning">
            This will: revoke all active sessions, create breach record, start the 60-day
            notification clock, and alert the compliance team.
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="breachType">Breach Type</Label>
            {/*
              <Select>, not a hand-rolled <select>. This restated CONTROL_BASE's
              styling but sized itself with `py-[11px]` and NO height, which is
              the exact failure controlStyles.ts exists to prevent: padding only
              yields a matching height while both controls have matching line
              boxes, and a select's is not an input's. Measured in the running
              app it came out 40.87px against the 43.99px <Input> two fields
              below it — two stacked fields in one form, 3px apart.
            */}
            <Select
              id="breachType"
              value={breachType}
              onChange={(e) => setBreachType(e.target.value)}
            >
              {BREACH_TYPES.map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
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
            {/* <Textarea> — this was a verbatim copy of that component's class
                string, which is one more place for the field language to drift
                from the one that owns it. */}
            <Textarea
              id="desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
            />
          </div>

          <div className="rounded-md border border-destructive/30 bg-destructive/[0.07] px-4 py-3 text-[13px] text-destructive">
            ⚠️ This action is irreversible and will be permanently logged. Only initiate
            for confirmed breaches.
          </div>

          <Button
            variant="destructive"
            onClick={onInitiate}
          >
            <AlertTriangle className="h-4 w-4" /> 🚨 Initiate Breach Workflow
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

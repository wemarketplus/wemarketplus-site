import { Copy } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { TempPasswordReveal } from '../hooks/useUserRowActions';
import { fullName } from '../utils/userDisplay';

interface TempPasswordDialogProps {
  reveal: TempPasswordReveal | null;
  onClose: () => void;
}

// One-time reveal of an admin-reset temporary password. The value is only
// returned once by the backend, so this dialog is the single chance to copy and
// relay it. The user must change it on next login.
export function TempPasswordDialog({ reveal, onClose }: TempPasswordDialogProps) {
  if (!reveal) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(reveal.temporaryPassword);
      toast.success('Temporary password copied');
    } catch {
      toast.error('Could not copy — select and copy it manually');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Temporary password"
      size="sm"
      footer={
        <Button onClick={onClose}>Done</Button>
      }
    >
      <p className="mb-4 text-sm text-muted">
        Share this one-time password with <span className="font-semibold text-foreground">{fullName(reveal.user)}</span>{' '}
        securely. It will not be shown again, and they must change it on next login.
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 select-all break-all rounded-md border border-white/[0.1] bg-surface-raised px-3 py-2.5 font-mono text-sm text-foreground">
          {reveal.temporaryPassword}
        </code>
        <Button variant="secondary" size="square" onClick={copy} aria-label="Copy temporary password">
          <Copy className="h-4 w-4" />
        </Button>
      </div>
    </Modal>
  );
}

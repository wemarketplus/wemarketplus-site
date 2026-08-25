import type { ReactNode } from 'react';
import { Button } from '@/shared/ui/core';
import { Modal } from './Modal';

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  /** What is about to happen, in the user's terms. */
  body?: ReactNode;
  /** Names the action rather than saying "OK" — "Delete company", "Merge 3 records". */
  confirmLabel: string;
  cancelLabel?: string;
  /** Red confirm button + irreversibility notice. Default true for destructive ops. */
  destructive?: boolean;
  /** Disables confirm while the action runs, and swaps the label. */
  isBusy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * In-app confirmation for destructive actions.
 *
 * Replaces `window.confirm`, which was used for every delete and for the company
 * merge. Native confirms are the wrong tool here for three reasons:
 *   1. They render as "localhost:5173 says" with no product styling, which reads as
 *      a browser malfunction rather than a deliberate safeguard.
 *   2. They accept only a string, so they cannot show WHAT is about to be affected
 *      — the company merge asked to approve a permanent hard delete with no
 *      indication of which records it would destroy.
 *   3. They block the JS event loop, which also freezes any automation driving the
 *      page.
 *
 * `confirmLabel` is required and should name the action ("Delete 4 companies"), not
 * acknowledge the question ("OK"). A button that says what it does is the last
 * chance to notice it is the wrong one.
 */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  cancelLabel = 'Cancel',
  destructive = true,
  isBusy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      size="sm"
      compact
      footer={
        <>
          {/*
            `secondary`, NOT `ghost` — the app's standard quiet button (32 other
            call sites), so Cancel wears the same hairline + raised wash as every
            other non-primary action.

            A previous pass moved this to `ghost` to stop the footer reading as
            "two equal choices". It over-corrected: ghost drops the border, the
            wash AND the text colour at once, leaving muted grey type floating on
            white next to a solid green pill — which is the low-visibility Cancel
            QA then reported. The hierarchy comes from only ONE button being
            FILLED; `bg-surface-raised` (#fafbfa) is a wash, not a fill, so
            Cancel stays clearly subordinate while still looking clickable.
          */}
          <Button variant="secondary" onClick={onCancel} disabled={isBusy}>
            {cancelLabel}
          </Button>
          {/*
            No weight override here on purpose: the filled variants themselves are
            700, not the 800 display weight, which is what fixed the "confirm
            button text is excessively bold" half of this report for every filled
            action at once. See the note at the top of Button.tsx.
          */}
          <Button
            variant={destructive ? 'destructive' : 'primary'}
            onClick={onConfirm}
            disabled={isBusy}
          >
            {isBusy ? 'Working…' : confirmLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-muted">
        {body}
        {destructive && (
          <p className="text-[12px] text-destructive">
            This cannot be undone.
          </p>
        )}
      </div>
    </Modal>
  );
}

import { useEffect } from 'react';
import { DemoButton } from '@/shared/cl-demo';
import { useMaxDemo } from '../hooks/useMaxDemo';

interface ModalShellProps {
  title: string;
  subtitle: string;
  borderColor: string;
  maxWidth: string;
  saveLabel: string;
  onSave: () => void;
  children: React.ReactNode;
}

// Reproduces the reference .op-modal shell: full-screen scrim, a bordered panel
// (slides up from the bottom on mobile), header with close, and Save/Cancel
// footer. Closes on Escape and scrim click.
export function ModalShell({ title, subtitle, borderColor, maxWidth, saveLabel, onSave, children }: ModalShellProps) {
  const { actions } = useMaxDemo();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') actions.closeModal(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [actions]);

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-end justify-center bg-black/[0.72] p-0 sm:items-center sm:p-4"
      onClick={(e) => { if (e.target === e.currentTarget) actions.closeModal(); }}
    >
      <div
        className={`max-h-[88vh] w-full overflow-y-auto rounded-t-[18px] bg-[#0a1628] p-7 sm:max-h-[92vh] sm:rounded-[18px] ${maxWidth}`}
        style={{ border: `1px solid ${borderColor}` }}
      >
        <div className="mb-5 flex items-center justify-between">
          <div>
            <div className="text-[16px] font-black text-[#f4f8ff]">{title}</div>
            <div className="mt-0.5 text-[11px] text-[#6b7fa3]">{subtitle}</div>
          </div>
          <button type="button" onClick={() => actions.closeModal()} className="cursor-pointer border-none bg-transparent text-[22px] leading-none text-[#6b7fa3]">×</button>
        </div>
        {children}
        <div className="mt-[18px] flex gap-2.5">
          <DemoButton className="flex-1 py-3 text-[14px]" onClick={onSave}>{saveLabel}</DemoButton>
          <DemoButton variant="x" onClick={() => actions.closeModal()}>Cancel</DemoButton>
        </div>
      </div>
    </div>
  );
}

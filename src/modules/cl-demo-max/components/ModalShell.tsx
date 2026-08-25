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
        {/*
          A REAL <form>, and `autoComplete="off"` on it.

          Every demo field was previously unowned — there was no <form> element
          anywhere in the three demo modules, so `field.form` was null for all of
          them. That is worse than an opted-out form, not neutral: Chrome groups
          unowned controls into a SYNTHETIC form scoped to the document, so this
          modal's fields were classified together with whatever else on the page
          happened to be formless — the tab's filter dropdowns and the sidebar's
          "viewing as" select. Giving the modal its own form boundary is what
          stops an autofill aimed at these fields reaching those.

          The `off` is belt to that braces: this modal offers Chrome a name, a
          `type="tel"` and a `type="email"`, which is the three-field threshold
          its address classifier needs, and once a form is classified the profile
          heuristics are applied to every control in it — `<select>`s included.
          That is how "Lead Source" and "Pipeline Stage" changed on their own.

          `onSubmit` is prevented and Save stays a button: the demo has no
          endpoint, and a real submit would reload the page and lose the demo's
          in-memory state. The form is here for the autofill boundary and for
          Enter-to-submit semantics, not to navigate.
        */}
        <form autoComplete="off" onSubmit={(e) => e.preventDefault()}>
          {children}
          <div className="mt-[18px] flex gap-2.5">
            <DemoButton className="flex-1 py-3 text-[14px]" onClick={onSave}>{saveLabel}</DemoButton>
            <DemoButton variant="x" onClick={() => actions.closeModal()}>Cancel</DemoButton>
          </div>
        </form>
      </div>
    </div>
  );
}

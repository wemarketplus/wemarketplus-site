import { Mic, MicOff } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { useVoiceDictation } from '@/shared/hooks';
import { cn } from '@/shared/utils/cn';

interface VoiceDictateButtonProps {
  /** Receives the full text as it grows, so the caller owns the field's value. */
  onTranscript: (text: string) => void;
  /** Existing field text, so dictation appends rather than replaces. */
  baseText?: string;
  className?: string;
}

/**
 * Windshield Voice Mode control — the "Voice Note button" the marketing copy already
 * claimed existed. Renders NOTHING when the browser cannot do speech recognition, rather
 * than showing a button that does nothing when pressed.
 *
 * The caller keeps ownership of the field value: this reports `baseText + transcript` on
 * every change instead of writing into the input itself, so typed and dictated text can
 * be mixed without the two fighting over the cursor.
 */
export function VoiceDictateButton({
  onTranscript,
  baseText = '',
  className,
}: VoiceDictateButtonProps) {
  const { isSupported, isListening, transcript, interim, error, start, stop } =
    useVoiceDictation();
  // The text present when dictation began, captured once, so restarting does not
  // concatenate the previous session's words a second time.
  const baseRef = useRef(baseText);

  useEffect(() => {
    if (!isListening) return;
    const combined = [baseRef.current, transcript].filter(Boolean).join(' ');
    onTranscript(combined);
  }, [transcript, isListening, onTranscript]);

  if (!isSupported) return null;

  const toggle = () => {
    if (isListening) {
      stop();
    } else {
      baseRef.current = baseText;
      start();
    }
  };

  return (
    <div className={cn('flex flex-col gap-1', className)}>
      <button
        type="button"
        onClick={toggle}
        aria-pressed={isListening}
        aria-label={isListening ? 'Stop dictation' : 'Dictate this note'}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
          isListening
            ? 'border-destructive/40 bg-destructive/10 text-destructive'
            : 'border-border/[0.12] text-muted hover:border-border/25 hover:text-foreground',
        )}
      >
        {isListening ? (
          <MicOff className="h-3.5 w-3.5" />
        ) : (
          <Mic className="h-3.5 w-3.5" />
        )}
        {isListening ? 'Listening — tap to stop' : 'Voice note'}
      </button>
      {isListening && interim && (
        // Showing interim words is what tells a driver it is actually hearing them.
        <p className="text-[11px] italic text-muted-soft">{interim}…</p>
      )}
      {error && <p className="text-[11px] text-destructive">{error}</p>}
      {isListening && (
        <p className="text-[10px] text-muted-soft">
          Recognised on this device — no audio leaves the browser.
        </p>
      )}
    </div>
  );
}

import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Windshield Voice Mode — hands-free dictation into a text field.
 *
 * Sold at Gold in four places (comparison table, landing copy, marketing constants,
 * pricing plans) and completely unbuilt: a grep for voice/mic/speech across the activity
 * module returned nothing, and the claim that it "is the Voice Note button in Notes" was
 * false — there was no such button.
 *
 * Uses the browser's SpeechRecognition (Web Speech API) rather than shipping audio to a
 * server. That is the right trade for this feature and not just the cheap one: a hospice
 * marketer dictating between visits is describing a patient, so the audio is PHI. Keeping
 * recognition on the device means no PHI audio is transmitted, stored, or retained by a
 * third-party transcription service — which would otherwise need a BAA before it could
 * legally be used at all.
 *
 * The cost is honest and surfaced: support is not universal (Chrome and Safari yes,
 * Firefox no), so `isSupported` is returned and callers must hide the control rather than
 * render a button that silently does nothing.
 *
 * Interim results are streamed so the driver sees words appear and knows it is listening;
 * only finalised segments are appended to the committed transcript.
 */

// Minimal structural types — the DOM lib does not ship SpeechRecognition, and pulling in
// a polyfill's types for four fields would be heavier than declaring them.
interface SpeechRecognitionAlternative {
  transcript: string;
}
interface SpeechRecognitionResult {
  0: SpeechRecognitionAlternative;
  isFinal: boolean;
}
interface SpeechRecognitionEventLike {
  resultIndex: number;
  results: { length: number; [index: number]: SpeechRecognitionResult };
}
interface SpeechRecognitionLike {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start: () => void;
  stop: () => void;
  onresult: ((event: SpeechRecognitionEventLike) => void) | null;
  onerror: ((event: { error: string }) => void) | null;
  onend: (() => void) | null;
}
type SpeechRecognitionCtor = new () => SpeechRecognitionLike;

function getRecognitionCtor(): SpeechRecognitionCtor | null {
  if (typeof window === 'undefined') return null;
  const w = window as unknown as {
    SpeechRecognition?: SpeechRecognitionCtor;
    webkitSpeechRecognition?: SpeechRecognitionCtor;
  };
  return w.SpeechRecognition ?? w.webkitSpeechRecognition ?? null;
}

export interface VoiceDictation {
  isSupported: boolean;
  isListening: boolean;
  /** Finalised text so far this session. */
  transcript: string;
  /** Words currently being recognised, not yet final. */
  interim: string;
  error: string | null;
  start: () => void;
  stop: () => void;
  reset: () => void;
}

export function useVoiceDictation(lang = 'en-US'): VoiceDictation {
  const [isListening, setIsListening] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [interim, setInterim] = useState('');
  const [error, setError] = useState<string | null>(null);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);
  const isSupported = getRecognitionCtor() !== null;

  const stop = useCallback(() => {
    recognitionRef.current?.stop();
    setIsListening(false);
    setInterim('');
  }, []);

  const start = useCallback(() => {
    const Ctor = getRecognitionCtor();
    if (!Ctor) {
      setError('This browser cannot do speech recognition.');
      return;
    }
    setError(null);
    const recognition = new Ctor();
    // continuous: a visit note is several sentences, and restarting per phrase would
    // make the driver keep reaching for the screen — the thing this feature avoids.
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = lang;

    recognition.onresult = (event) => {
      let finalText = '';
      let pending = '';
      for (let i = event.resultIndex; i < event.results.length; i += 1) {
        const result = event.results[i];
        if (result.isFinal) finalText += result[0].transcript;
        else pending += result[0].transcript;
      }
      if (finalText) {
        setTranscript((prev) => (prev ? `${prev} ${finalText.trim()}` : finalText.trim()));
      }
      setInterim(pending);
    };
    recognition.onerror = (event) => {
      // `no-speech` and `aborted` are normal in a car; only report the rest, so the UI
      // does not cry wolf at a pause in dictation.
      if (event.error !== 'no-speech' && event.error !== 'aborted') {
        setError(
          event.error === 'not-allowed'
            ? 'Microphone permission was denied.'
            : `Dictation stopped: ${event.error}`,
        );
      }
      setIsListening(false);
    };
    recognition.onend = () => {
      setIsListening(false);
      setInterim('');
    };

    recognitionRef.current = recognition;
    recognition.start();
    setIsListening(true);
  }, [lang]);

  const reset = useCallback(() => {
    setTranscript('');
    setInterim('');
    setError(null);
  }, []);

  // Stop the microphone if the component unmounts mid-session — a hot mic left running
  // after the form closes is both a privacy problem and a battery one.
  useEffect(() => () => recognitionRef.current?.stop(), []);

  return { isSupported, isListening, transcript, interim, error, start, stop, reset };
}

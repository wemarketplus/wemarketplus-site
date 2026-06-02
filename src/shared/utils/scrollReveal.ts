import type { CSSProperties } from 'react';
import { cn } from './cn';
import {
  REVEAL_HIDDEN,
  REVEAL_SHOWN,
  REVEAL_STAGGER_STEP_MS,
} from '@/shared/constants/motionConstants';

// Pure helpers for the scroll-reveal pattern (see useScrollReveal). No side
// effects, no hooks — safe to call inline during render.

// Compose the reveal className for an element given its current visibility.
// `extra` is merged last so callers can layer section-specific classes.
export function revealClass(visible: boolean, extra?: string): string {
  return cn(visible ? REVEAL_SHOWN : REVEAL_HIDDEN, extra);
}

// Stagger delay for the nth revealing child. Returns undefined for the first
// item (or while hidden) so no needless inline style is attached. Drives the
// `reveal` keyframe's animation-delay — independent of any hover transition.
export function staggerStyle(
  index: number,
  visible: boolean,
  stepMs: number = REVEAL_STAGGER_STEP_MS,
): CSSProperties | undefined {
  if (!visible || index <= 0) return undefined;
  return { animationDelay: `${index * stepMs}ms` };
}

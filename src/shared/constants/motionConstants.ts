// Shared scroll-reveal motion tokens, used across the marketing landing
// sections (features, origin, workflow, vs-generic, testimonials, pricing).
// These drive the *existing* `reveal` keyframe (tailwind.config.js: opacity
// 0→1, translateY 24px→0, 0.8s eased) — no animation library, no new keyframes.
//
// Pair with `useScrollReveal` (orchestration) and `scrollReveal` utils
// (className/stagger composition). Static values only — see modular rules.

// Pre-reveal: element waits invisible until scrolled into view. Reduced-motion
// users skip straight to visible (no hidden flash, no dependence on JS).
export const REVEAL_HIDDEN = 'opacity-0 motion-reduce:opacity-100';

// Revealed: replays the `reveal` keyframe. Under prefers-reduced-motion the
// animation is suppressed and the element simply renders at its natural state.
export const REVEAL_SHOWN = 'animate-reveal motion-reduce:animate-none';

// Per-child stagger increment (ms) for elegant, subtle cascades.
export const REVEAL_STAGGER_STEP_MS = 90;

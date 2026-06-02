import { useEffect, useRef, useState } from 'react';

interface ScrollRevealOptions {
  // Fraction of the element that must be visible before revealing (0–1).
  threshold?: number;
  // IntersectionObserver rootMargin — default trips slightly before the
  // element's bottom edge enters the viewport for a natural feel.
  rootMargin?: string;
  // Reveal only once (default). When false, the element re-hides on exit.
  once?: boolean;
}

// Flips `visible` to true when the referenced element scrolls into view, then
// (by default) stops observing. GPU-friendly: callers drive opacity/transform
// only. Falls back to immediately-visible when IntersectionObserver is missing
// so content is never stranded hidden. Reduced-motion is handled at the
// className layer (see scrollReveal utils), not here.
export function useScrollReveal<T extends HTMLElement = HTMLDivElement>({
  threshold = 0.15,
  rootMargin = '0px 0px -10% 0px',
  once = true,
}: ScrollRevealOptions = {}) {
  const ref = useRef<T>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;

    if (typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          if (once) observer.disconnect();
        } else if (!once) {
          setVisible(false);
        }
      },
      { threshold, rootMargin },
    );

    observer.observe(node);
    return () => observer.disconnect();
  }, [threshold, rootMargin, once]);

  return { ref, visible };
}

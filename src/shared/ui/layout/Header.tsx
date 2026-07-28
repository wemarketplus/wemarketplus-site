import { Logo } from '@/shared/ui/core/Logo';

// Lightweight header for any non-authenticated screens that aren't the
// centered auth card (e.g. a future marketing-style status page).
export function Header() {
  return (
    <header className="flex h-16 items-center justify-between border-b border-border/[0.06] bg-bg/80 px-6 backdrop-blur-sm">
      <Logo />
    </header>
  );
}

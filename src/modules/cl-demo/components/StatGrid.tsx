// Reproduces the reference .stats grid: auto-fit columns, min 140px, 12px gap.
export function StatGrid({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-4 grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(140px,1fr))]">
      {children}
    </div>
  );
}

// Labeled field wrapper used by the Notes add-note form (rNotes). Distinct from
// the shared Field — uses the Notes form's muted label styling.
export function Fld({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-[11px] font-bold text-[#4b6278]">{label}</div>
      {children}
    </div>
  );
}

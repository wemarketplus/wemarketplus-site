// Mirrors the live site's sticky "Jump to: Hospice CRM / Senior Living CRM"
// sub-nav under the main header. Anchors to the on-page product sections.
export function JumpToBar() {
  return (
    <div className="sticky top-16 z-20 border-b border-white/[0.06] bg-bg/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-center gap-3 px-6 py-3 text-[13px]">
        <span className="text-muted-soft">Jump to:</span>
        <a
          href="#hospicelink"
          className="rounded-pill border border-sage/40 bg-sage/10 px-3.5 py-1.5 font-semibold text-sage hover:bg-sage/20"
        >
          ♥ Hospice CRM
        </a>
        <a
          href="#communitylink"
          className="rounded-pill border border-amber/40 bg-amber/10 px-3.5 py-1.5 font-semibold text-amber hover:bg-amber/20"
        >
          🏠 Senior Living CRM
        </a>
      </div>
    </div>
  );
}

// Strips undefined / empty-string values from a list-query params object so a
// blank search box or "All" filter never sends an empty query param the backend
// DTO would reject. Returns undefined when nothing is left (so RTK Query omits
// the params entirely). Shared by the CommunityLink list modules.
export function cleanListParams(
  params?: object | null,
): Record<string, string | number> | undefined {
  if (!params) return undefined;
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '' && value !== null) {
      out[key] = value as string | number;
    }
  }
  return Object.keys(out).length ? out : undefined;
}

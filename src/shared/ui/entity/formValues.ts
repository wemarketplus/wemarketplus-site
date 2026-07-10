// Helpers for turning RHF form values into a DTO body the backend accepts.
// The backend runs `forbidNonWhitelisted` + rejects empty strings on optional
// fields, so blank optionals must be dropped rather than sent as "".

// Returns the trimmed string, or undefined when blank — for optional string DTO
// fields. Spread the result: `...opt('email', v.email)`.
export function opt(key: string, value: string | undefined | null): Record<string, string> {
  const trimmed = value?.trim();
  return trimmed ? { [key]: trimmed } : {};
}

// Same as `opt` but for numeric fields. NaN (empty number input) is dropped.
export function optNum(key: string, value: number | undefined | null): Record<string, number> {
  return value === undefined || value === null || Number.isNaN(value) ? {} : { [key]: value };
}

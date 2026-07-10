// Backend runtime feature flags — wemarketplus-backend/src/feature-flags.
//   GET /feature-flags        -> EffectiveFlags (key -> boolean) for the tenant
//   GET /admin/feature-flags  -> FeatureFlag[] (super_admin management view)
//   PUT /admin/feature-flags/:key { enabled, tenantId? } -> FeatureFlag
// These are operator-toggleable switches (rollouts / kill-switches), distinct
// from plan-tier gating (billing) enforced by @RequireFeature on the backend.

/** Resolved on/off state of every flag for the caller's tenant. */
export type EffectiveFlags = Record<string, boolean>;

/** A flag record as returned to the SuperAdmin management screen. */
export interface FeatureFlag {
  key: string;
  description: string;
  enabledGlobally: boolean;
  overrides: Record<string, boolean>;
}

export interface UpdateFeatureFlagRequest {
  key: string;
  enabled: boolean;
  /** When set, updates this tenant's override instead of the global default. */
  tenantId?: string;
}

// Backend permission-matrix keys — mirror wemarketplus-backend/src/permissions
// (the grant-CRM permission keys, distinct from the descriptive role-capability
// guide in permissionsConstants).
export const PERMISSION_KEYS = [
  'view_records',
  'create_wibs_companies',
  'edit_wibs_companies',
  'delete_records',
  'create_edit_apps',
  'view_revenue',
  'manage_invoices',
  'compliance_tracking',
  'notes_tasks',
  'ai_assistant',
  'import_export',
  'audit_logs',
  'manage_users',
  'assign_roles',
  'assign_super_admin',
  'system_settings',
] as const;

export type PermissionKey = (typeof PERMISSION_KEYS)[number];

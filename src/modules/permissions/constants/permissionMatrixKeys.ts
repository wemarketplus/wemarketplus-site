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

// Human-readable labels for each permission key, shown as the matrix row labels.
export const PERMISSION_LABELS: Record<PermissionKey, string> = {
  view_records: 'View records',
  create_wibs_companies: 'Create companies',
  edit_wibs_companies: 'Edit companies',
  delete_records: 'Delete records',
  create_edit_apps: 'Create / edit applications',
  view_revenue: 'View revenue',
  manage_invoices: 'Manage invoices',
  compliance_tracking: 'Compliance tracking',
  notes_tasks: 'Notes & tasks',
  ai_assistant: 'AI assistant',
  import_export: 'Import / export',
  audit_logs: 'Audit logs',
  manage_users: 'Manage users',
  assign_roles: 'Assign roles',
  assign_super_admin: 'Assign super admin',
  system_settings: 'System settings',
};

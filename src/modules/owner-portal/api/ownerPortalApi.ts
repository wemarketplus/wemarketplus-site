// TODO(backend): owner-portal endpoints — none exist today. When they ship,
// define an RTK Query slice with endpoints like:
//   GET /owner/kpis
//   GET /owner/revenue?range=12m
//   GET /owner/customers?page=&status=
//   GET /owner/pipeline
//   GET /owner/visitors?range=24h
//   GET /owner/churn-risk
//   GET /owner/usage
//   GET /owner/insights
//   GET /owner/communications
//   GET /owner/audit
// Owner-only — gate at the route level with <ProtectedRoute allow={['admin']}>
// once auth gating is re-enabled.
export {};

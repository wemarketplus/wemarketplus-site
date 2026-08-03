import { combineReducers, configureStore } from '@reduxjs/toolkit';
import { setupListeners } from '@reduxjs/toolkit/query';
import {
  persistReducer,
  persistStore,
  FLUSH,
  PAUSE,
  PERSIST,
  PURGE,
  REGISTER,
  REHYDRATE,
} from 'redux-persist';
import storage from 'redux-persist/lib/storage';

import { accessReducer } from '@/modules/access';
import { activityApi, activityReducer } from '@/modules/activity';
import { adminApi } from '@/modules/admin';
import { agreementsApi } from '@/modules/agreements';
import { aiAssistantReducer } from '@/modules/ai-assistant';
import { applicationsApi } from '@/modules/applications';
import { appointmentsApi, appointmentsReducer } from '@/modules/appointments';
import { authApi, authReducer } from '@/modules/auth';
import { chatApi } from '@/modules/chat';
import { documentsApi } from '@/modules/documents';
import { financeApi } from '@/modules/finance';
import { fundingApi } from '@/modules/funding';
import { trainingApi } from '@/modules/training-providers';
import { wibsApi } from '@/modules/wibs';
import { billingApi, billingReducer } from '@/modules/billing';
import { adminSettingsApi as clAdminSettingsApi } from '@/modules/cl-admin-settings';
import { giftGratuityApi } from '@/modules/cl-gift-gratuity';
import { clFinancialApi } from '@/modules/cl-financial';
import { clDemoReducer } from '@/modules/cl-demo';
import { goldDemoReducer } from '@/modules/cl-demo-gold';
import { maxDemoReducer } from '@/modules/cl-demo-max';
import { leadsApi as clLeadsApi } from '@/modules/cl-leads';
import { clOperationsApi, clOperationsReducer } from '@/modules/cl-operations';
import { clOutreachApi, clOutreachReducer } from '@/modules/cl-outreach';
import { clReferralsApi } from '@/modules/cl-referrals';
import { clReportsReducer, clReportsApi } from '@/modules/cl-reports';
import { clToursApi } from '@/modules/cl-tours';
import { clinicalApi, clinicalReducer } from '@/modules/clinical';
import { companiesApi } from '@/modules/companies';
import { complianceApi, complianceReducer } from '@/modules/compliance';
import { contactsApi } from '@/modules/contacts';
import { invoicesApi } from '@/modules/invoices';
import { jobsApi, jobsReducer } from '@/modules/jobs';
import { leadsApi, leadsReducer } from '@/modules/leads';
import { contractsApi } from '@/modules/contracts';
import { locationsApi } from '@/modules/locations';
import { territoriesApi } from '@/modules/territories';
import { dashboardApi, dashboardReducer, reportsApi } from '@/modules/dashboard';
import { featureFlagsApi, featureFlagsReducer } from '@/modules/feature-flags';
import { integrationsApi, integrationsReducer } from '@/modules/integrations';
import { intelligenceReducer } from '@/modules/intelligence';
import { marketingReducer } from '@/modules/marketing';
import { notificationsApi, notificationsReducer } from '@/modules/notifications';
import { onboardingApi, onboardingReducer } from '@/modules/onboarding';
import { impersonationApi, ownerPortalApi, ownerPortalReducer } from '@/modules/owner-portal';
import { permissionsApi, permissionsReducer } from '@/modules/permissions';
import { pipelineApi, pipelineReducer } from '@/modules/pipeline';
import { prospectsApi, prospectsReducer } from '@/modules/prospects';
import { referralsApi, referralsReducer } from '@/modules/referrals';
import { hospiceContactsApi } from '@/modules/hospice-contacts/api/hospiceContactsApi';
import { schedulingReducer } from '@/modules/scheduling';
import { settingsApi, settingsReducer } from '@/modules/settings';
import { usersApi, usersReducer } from '@/modules/users';

const rootReducer = combineReducers({
  // Sorted alphabetically so it's easy to spot a missing slice when wiring
  // a new module.
  access: accessReducer,
  activity: activityReducer,
  aiAssistant: aiAssistantReducer,
  appointments: appointmentsReducer,
  auth: authReducer,
  billing: billingReducer,
  clDemo: clDemoReducer,
  clOperations: clOperationsReducer,
  clOutreach: clOutreachReducer,
  clReports: clReportsReducer,
  clinical: clinicalReducer,
  compliance: complianceReducer,
  dashboard: dashboardReducer,
  featureFlags: featureFlagsReducer,
  goldDemo: goldDemoReducer,
  maxDemo: maxDemoReducer,
  integrations: integrationsReducer,
  intelligence: intelligenceReducer,
  jobs: jobsReducer,
  leads: leadsReducer,
  marketing: marketingReducer,
  notifications: notificationsReducer,
  onboarding: onboardingReducer,
  ownerPortal: ownerPortalReducer,
  permissions: permissionsReducer,
  pipeline: pipelineReducer,
  prospects: prospectsReducer,
  referrals: referralsReducer,
  scheduling: schedulingReducer,
  settings: settingsReducer,
  users: usersReducer,
  [activityApi.reducerPath]: activityApi.reducer,
  [adminApi.reducerPath]: adminApi.reducer,
  [agreementsApi.reducerPath]: agreementsApi.reducer,
  [applicationsApi.reducerPath]: applicationsApi.reducer,
  [appointmentsApi.reducerPath]: appointmentsApi.reducer,
  [authApi.reducerPath]: authApi.reducer,
  [billingApi.reducerPath]: billingApi.reducer,
  [clAdminSettingsApi.reducerPath]: clAdminSettingsApi.reducer,
  [giftGratuityApi.reducerPath]: giftGratuityApi.reducer,
  [clReportsApi.reducerPath]: clReportsApi.reducer,
  [clFinancialApi.reducerPath]: clFinancialApi.reducer,
  [clLeadsApi.reducerPath]: clLeadsApi.reducer,
  [clOperationsApi.reducerPath]: clOperationsApi.reducer,
  [clOutreachApi.reducerPath]: clOutreachApi.reducer,
  [clReferralsApi.reducerPath]: clReferralsApi.reducer,
  [clToursApi.reducerPath]: clToursApi.reducer,
  [clinicalApi.reducerPath]: clinicalApi.reducer,
  [chatApi.reducerPath]: chatApi.reducer,
  [companiesApi.reducerPath]: companiesApi.reducer,
  [complianceApi.reducerPath]: complianceApi.reducer,
  [contactsApi.reducerPath]: contactsApi.reducer,
  [invoicesApi.reducerPath]: invoicesApi.reducer,
  [jobsApi.reducerPath]: jobsApi.reducer,
  [leadsApi.reducerPath]: leadsApi.reducer,
  [contractsApi.reducerPath]: contractsApi.reducer,
  [dashboardApi.reducerPath]: dashboardApi.reducer,
  [documentsApi.reducerPath]: documentsApi.reducer,
  [featureFlagsApi.reducerPath]: featureFlagsApi.reducer,
  [impersonationApi.reducerPath]: impersonationApi.reducer,
  [financeApi.reducerPath]: financeApi.reducer,
  [fundingApi.reducerPath]: fundingApi.reducer,
  [locationsApi.reducerPath]: locationsApi.reducer,
  [territoriesApi.reducerPath]: territoriesApi.reducer,
  [trainingApi.reducerPath]: trainingApi.reducer,
  [wibsApi.reducerPath]: wibsApi.reducer,
  [integrationsApi.reducerPath]: integrationsApi.reducer,
  [notificationsApi.reducerPath]: notificationsApi.reducer,
  [onboardingApi.reducerPath]: onboardingApi.reducer,
  [ownerPortalApi.reducerPath]: ownerPortalApi.reducer,
  [permissionsApi.reducerPath]: permissionsApi.reducer,
  [pipelineApi.reducerPath]: pipelineApi.reducer,
  [prospectsApi.reducerPath]: prospectsApi.reducer,
  [referralsApi.reducerPath]: referralsApi.reducer,
  [hospiceContactsApi.reducerPath]: hospiceContactsApi.reducer,
  [reportsApi.reducerPath]: reportsApi.reducer,
  [settingsApi.reducerPath]: settingsApi.reducer,
  [usersApi.reducerPath]: usersApi.reducer,
});

export type RootState = ReturnType<typeof rootReducer>;

const persistConfig = {
  key: 'wemarketplus-root',
  version: 1,
  storage,
  // Only auth + the active-dashboard selection survive reloads — server state is
  // fetched fresh via RTK Query. Onboarding draft persists via its own slice's
  // localStorage write (TTL).
  whitelist: ['auth', 'access'],
};

// persistReducer's generic widens the state type and confuses the
// middleware tuple inference. Casting the persisted reducer back to the
// non-persisted Reducer<RootState> shape lets RTK Query middleware compose
// cleanly while still giving us redux-persist's runtime behavior.
const persistedReducer = persistReducer(
  persistConfig,
  rootReducer,
) as unknown as typeof rootReducer;

export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER],
      },
    }).concat(
      activityApi.middleware,
      adminApi.middleware,
      agreementsApi.middleware,
      applicationsApi.middleware,
      appointmentsApi.middleware,
      authApi.middleware,
      billingApi.middleware,
      clAdminSettingsApi.middleware,
      giftGratuityApi.middleware,
      clReportsApi.middleware,
      clFinancialApi.middleware,
      clLeadsApi.middleware,
      clOperationsApi.middleware,
      clOutreachApi.middleware,
      clReferralsApi.middleware,
      clToursApi.middleware,
      clinicalApi.middleware,
      chatApi.middleware,
      companiesApi.middleware,
      complianceApi.middleware,
      contactsApi.middleware,
      invoicesApi.middleware,
      jobsApi.middleware,
      leadsApi.middleware,
      contractsApi.middleware,
      dashboardApi.middleware,
      documentsApi.middleware,
      featureFlagsApi.middleware,
      impersonationApi.middleware,
      financeApi.middleware,
      fundingApi.middleware,
      locationsApi.middleware,
      territoriesApi.middleware,
      trainingApi.middleware,
      wibsApi.middleware,
      integrationsApi.middleware,
      notificationsApi.middleware,
      onboardingApi.middleware,
      ownerPortalApi.middleware,
      permissionsApi.middleware,
      pipelineApi.middleware,
      prospectsApi.middleware,
      referralsApi.middleware,
      hospiceContactsApi.middleware,
      reportsApi.middleware,
      settingsApi.middleware,
      usersApi.middleware,
    ),
});

export const persistor = persistStore(store);

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;

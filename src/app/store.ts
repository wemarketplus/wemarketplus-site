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

import { activityReducer } from '@/modules/activity';
import { aiAssistantReducer } from '@/modules/ai-assistant';
import { authApi, authReducer } from '@/modules/auth';
import { billingApi, billingReducer } from '@/modules/billing';
import { clFinancialReducer } from '@/modules/cl-financial';
import { clDemoReducer } from '@/modules/cl-demo';
import { clLeadsReducer } from '@/modules/cl-leads';
import { clOperationsReducer } from '@/modules/cl-operations';
import { clOutreachReducer } from '@/modules/cl-outreach';
import { clReferralsReducer } from '@/modules/cl-referrals';
import { clReportsReducer } from '@/modules/cl-reports';
import { clToursReducer } from '@/modules/cl-tours';
import { clinicalReducer } from '@/modules/clinical';
import { complianceReducer } from '@/modules/compliance';
import { dashboardReducer } from '@/modules/dashboard';
import { integrationsReducer } from '@/modules/integrations';
import { intelligenceReducer } from '@/modules/intelligence';
import { marketingReducer } from '@/modules/marketing';
import { notificationsApi, notificationsReducer } from '@/modules/notifications';
import { onboardingApi, onboardingReducer } from '@/modules/onboarding';
import { ownerPortalReducer } from '@/modules/owner-portal';
import { permissionsReducer } from '@/modules/permissions';
import { pipelineReducer } from '@/modules/pipeline';
import { prospectsApi, prospectsReducer } from '@/modules/prospects';
import { referralsApi, referralsReducer } from '@/modules/referrals';
import { schedulingReducer } from '@/modules/scheduling';
import { settingsReducer } from '@/modules/settings';
import { usersApi, usersReducer } from '@/modules/users';

const rootReducer = combineReducers({
  // Sorted alphabetically so it's easy to spot a missing slice when wiring
  // a new module.
  activity: activityReducer,
  aiAssistant: aiAssistantReducer,
  auth: authReducer,
  billing: billingReducer,
  clDemo: clDemoReducer,
  clFinancial: clFinancialReducer,
  clLeads: clLeadsReducer,
  clOperations: clOperationsReducer,
  clOutreach: clOutreachReducer,
  clReferrals: clReferralsReducer,
  clReports: clReportsReducer,
  clTours: clToursReducer,
  clinical: clinicalReducer,
  compliance: complianceReducer,
  dashboard: dashboardReducer,
  integrations: integrationsReducer,
  intelligence: intelligenceReducer,
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
  [authApi.reducerPath]: authApi.reducer,
  [billingApi.reducerPath]: billingApi.reducer,
  [notificationsApi.reducerPath]: notificationsApi.reducer,
  [onboardingApi.reducerPath]: onboardingApi.reducer,
  [prospectsApi.reducerPath]: prospectsApi.reducer,
  [referralsApi.reducerPath]: referralsApi.reducer,
  [usersApi.reducerPath]: usersApi.reducer,
});

export type RootState = ReturnType<typeof rootReducer>;

const persistConfig = {
  key: 'wemarketplus-root',
  version: 1,
  storage,
  // Only auth survives reloads — server state is fetched fresh via RTK Query.
  // Onboarding draft persists via its own slice's localStorage write (TTL).
  whitelist: ['auth'],
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
      authApi.middleware,
      billingApi.middleware,
      notificationsApi.middleware,
      onboardingApi.middleware,
      prospectsApi.middleware,
      referralsApi.middleware,
      usersApi.middleware,
    ),
});

export const persistor = persistStore(store);

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;

// Barrel for design-only seed data. Import via `@/shared/fixtures`. Every
// consumer in `modules/*/api/*Api.ts` should be marked with a `TODO: wire to
// backend` comment so we can grep them out when real endpoints ship.
export * from './hospicelinkFixtures';
export * from './communitylinkFixtures';
export * from './sharedFixtures';

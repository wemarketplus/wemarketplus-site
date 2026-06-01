# wemarketplus-frontend

React + TypeScript + Vite frontend for the **WeMarketPlus CRM** ([wemarketplus-backend](../wemarketplus-backend)). Architecture follows the **bulletproof-react** feature-based pattern.

## Quick start

```bash
npm install
npm run dev   # http://localhost:3001
```

The dev server proxies `/api/*` to `http://localhost:3000` (the NestJS backend). Make sure the backend is running first.

## Architecture

```
src/
├── app/        # Bootstrap: store, providers, router, baseQuery
├── modules/    # Feature domains. Each owns: api/ components/ constants/ hooks/ pages/ schema/ store/ types/ utils/
│   ├── auth          # Login / current user
│   ├── dashboard     # Home shell (stub — backend not wired)
│   ├── permissions   # Roles & capabilities matrix (admin-only)
│   └── users         # User CRUD
├── routes/     # Route guards (ProtectedRoute, PublicRoute)
└── shared/     # Cross-cutting code (ui, rbac, hooks, contexts, types, utils, config)
```

### Dependency direction

`shared → modules → app`. A module may import from `shared/` but **must not** import another module's internals — only its public barrel (`@/modules/<name>`). This isn't lint-enforced yet; keep it honest manually.

### State strategy

- **Redux Toolkit** for client state that needs to be observed across the tree. Each module that needs slice state owns one under `store/`, combined in `app/store.ts`.
- **RTK Query** for all server state (lists, details, mutations). One API slice per module under `api/`.
- **Redux Persist** whitelists only the `auth` slice (token + user). Everything else is fetched fresh.
- **React Context** is reserved for pure UI state (e.g. `ThemeContext`). Don't reach for it for data.

### RBAC

The backend is **role-based, not permission-based** — roles are `admin | manager | rep`, embedded in the JWT and returned on `/auth/me`. The frontend mirrors that exactly:

- `shared/rbac/` — *enforcement*: `<RoleGate allow={['admin']}>`, `useRole()` hook, `Role` constants. Use these to gate UI.
- `modules/permissions/` — reserved for a future admin CRUD over permission records, **if** the backend grows a permission table. Today it's a stub.

This boundary is documented at the top of each barrel; don't blur it.

### Theming

Single source of truth: CSS custom properties on `:root` (light) and `.dark` (`src/index.css`). Tailwind maps semantic names (`bg-background`, `text-foreground`, `bg-primary`) to those vars. `ThemeContext` toggles the `.dark` class on `<html>`. Avoid hard-coded hex values in components.

### File naming (enforced by convention, not lint)

- Components: `PascalCase.tsx`
- Hooks: `camelCase.ts` with `use` prefix
- Utility / config / type / store files: `camelCase.ts`
- Folders: `lowercase-kebab`
- Barrels: `index.ts`

## Backend coupling

API contracts live in `src/modules/*/types/`. They're hand-mirrored from the NestJS DTOs at `wemarketplus-backend/src/**/dto/`. If you change a DTO in the backend, update the matching type here.

- Auth: `POST /auth/login`, `GET /auth/me`, `POST /auth/register`
- Users: `GET|POST /users`, `GET|PATCH|DELETE /users/:id`, `PATCH /users/me`

All responses are wrapped in `{ data: ... }`; lists return `{ data: T[], total: number }`. Errors come back as `{ statusCode, message, timestamp, path }`.

## TODOs / known gaps

- No `/auth/refresh` endpoint yet — `baseQuery` logs out on 401 and redirects. When the backend ships refresh tokens, restore the mutex-guarded refresh flow.
- The `dashboard` and `permissions` modules render static content until the backend exposes analytics and/or a permission resource. See the TODO comments inside each module's `api/` file.
- No error boundary, no test setup, no Storybook — add as the codebase grows.

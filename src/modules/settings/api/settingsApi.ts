// settings/ does not own its own server endpoints today. Each tab reuses
// the owning module's RTK Query slice:
//   - Profile tab    → @/modules/users (PATCH /users/me)
//   - Organization   → TODO when /organizations is exposed
//   - Integrations   → TODO when /integrations is exposed
//   - Security       → reads from @/modules/auth and links to /account/password
//
// Keeping this file as a module placeholder so the folder layout stays
// symmetric across modules. Add an RTK Query slice here if settings grows
// endpoints of its own.
export {};

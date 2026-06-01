// Mirrors wemarketplus-backend/src/users/users.constants.ts.
export const PASSWORD_MIN_LENGTH = 8;
export const NAME_MIN_LENGTH = 1;
export const NAME_MAX_LENGTH = 120;

// Backend caps `limit` at 100 (see common/dto/pagination.dto.ts). We pick a
// sensible default page size for the UI table.
export const DEFAULT_PAGE_SIZE = 20;

export const USERS_TAGS = {
  List: 'Users.List',
  Detail: 'Users.Detail',
} as const;

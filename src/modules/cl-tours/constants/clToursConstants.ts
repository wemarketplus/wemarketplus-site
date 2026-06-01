import type { Tour } from '@/shared/types';

export const TOUR_TYPE_LABEL: Record<Tour['tourType'], string> = {
  in_person: 'In-person',
  virtual: 'Virtual',
  phone: 'Phone',
};

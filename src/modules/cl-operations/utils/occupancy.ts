import { ApartmentStatus, type Apartment } from '@/shared/types';

export function occupancyRate(apartments: readonly Apartment[]): number {
  if (apartments.length === 0) return 0;
  const occupied = apartments.filter(
    (a) => a.status === ApartmentStatus.Occupied || a.status === ApartmentStatus.Reserved,
  ).length;
  return occupied / apartments.length;
}

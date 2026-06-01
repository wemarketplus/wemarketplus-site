export type ID = string;

export type ISODateString = string;

export type Nullable<T> = T | null;

export interface TimestampedEntity {
  id: ID;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

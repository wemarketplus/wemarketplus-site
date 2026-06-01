import { formatDate } from '@/shared/utils/dateFormatter';
import { SubscriptionStatus } from '@/shared/types';

export const statusLabel = (status: SubscriptionStatus): string => {
  switch (status) {
    case SubscriptionStatus.Active:
      return 'Active';
    case SubscriptionStatus.PastDue:
      return 'Past due';
    case SubscriptionStatus.Suspended:
      return 'Suspended';
    case SubscriptionStatus.Canceled:
      return 'Canceled';
  }
};

export const statusToneClass = (status: SubscriptionStatus): string => {
  switch (status) {
    case SubscriptionStatus.Active:
      return 'border-success/30 bg-success/10 text-success';
    case SubscriptionStatus.PastDue:
      return 'border-warning/30 bg-warning/10 text-warning';
    case SubscriptionStatus.Suspended:
    case SubscriptionStatus.Canceled:
      return 'border-destructive/30 bg-destructive/10 text-destructive';
  }
};

export const formatPeriodEnd = (iso: string): string => formatDate(iso, 'PPP');

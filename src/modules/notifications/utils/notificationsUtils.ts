import { AlertTriangle, Bell, CheckCheck, MessageSquare } from 'lucide-react';
import type { ComponentType } from 'react';
import type { AppNotification } from '@/shared/types';

export const categoryIcon = (category: AppNotification['category']): ComponentType<{ className?: string }> => {
  switch (category) {
    case 'alert':
      return AlertTriangle;
    case 'task':
      return CheckCheck;
    case 'mention':
      return MessageSquare;
    case 'system':
      return Bell;
  }
};

export const categoryToneClass = (category: AppNotification['category']): string => {
  switch (category) {
    case 'alert':
      return 'text-warning';
    case 'task':
      return 'text-primary';
    case 'mention':
      return 'text-azure';
    case 'system':
      return 'text-muted';
  }
};

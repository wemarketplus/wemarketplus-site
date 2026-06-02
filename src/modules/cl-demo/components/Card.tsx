import { cn } from '@/shared/utils/cn';
import { CARD, CARD_HEAD, CARD_TITLE } from '../constants/clDemoStyles';

interface CardProps {
  title?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

// Reproduces the reference .card / .card-hd / .card-t. When `title` is given a
// header row renders with an optional right-aligned `action`.
export function Card({ title, action, children, className }: CardProps) {
  return (
    <div className={cn(CARD, className)}>
      {(title || action) && (
        <div className={CARD_HEAD}>
          {typeof title === 'string' ? <div className={CARD_TITLE}>{title}</div> : title}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

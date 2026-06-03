import { cn } from '@/shared/utils/cn';
import { BTN_A, BTN_BASE, BTN_G, BTN_R, BTN_SM, BTN_X } from '../styles';

type DemoButtonVariant = 'a' | 'g' | 'x' | 'r';

const VARIANT: Record<DemoButtonVariant, string> = {
  a: BTN_A,
  g: BTN_G,
  x: BTN_X,
  r: BTN_R,
};

interface DemoButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: DemoButtonVariant;
  sm?: boolean;
}

// Reproduces the reference .btn (.btn-a/.btn-g/.btn-x/.btn-r, .btn-sm).
export function DemoButton({
  variant = 'a',
  sm = false,
  className,
  type = 'button',
  ...rest
}: DemoButtonProps) {
  return (
    <button
      type={type}
      className={cn(BTN_BASE, VARIANT[variant], sm && BTN_SM, className)}
      {...rest}
    />
  );
}

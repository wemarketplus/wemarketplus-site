import { cn } from '@/shared/utils/cn';
import type { AiMessage } from '../types/aiAssistantTypes';

export function AiMessageBubble({ message }: { message: AiMessage }) {
  const isUser = message.role === 'user';
  return (
    <div className={cn('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div
        className={cn(
          'max-w-[80%] rounded-lg px-4 py-2.5 text-sm',
          isUser
            ? 'bg-primary/15 text-foreground'
            : 'border border-white/[0.06] bg-white/[0.02] text-foreground',
        )}
      >
        {message.content}
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from 'react';
import { Card } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { cn } from '@/shared/utils/cn';
import { AI_QUICK_PROMPTS } from '../constants/clDemoData';
import { FI } from '@/shared/cl-demo';
import { useAiAssistant } from '../hooks/useAiAssistant';

// AI Sales Assistant tab — reproduces rAI(): chat panel + quick prompts. The
// request is keyless (as in the live demo) so replies surface "AI unavailable".
export function AiAssistantTab() {
  const { messages, send, clear } = useAiAssistant();
  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages]);

  const submit = () => {
    const v = input.trim();
    if (!v) return;
    setInput('');
    void send(v);
  };

  return (
    <div className="grid grid-cols-1 gap-[14px] lg:[grid-template-columns:2fr_1fr]">
      <Card
        title="AI Sales Assistant"
        action={<DemoButton variant="x" sm onClick={clear}>Clear</DemoButton>}
      >
        <div
          ref={scrollRef}
          className="mb-2.5 flex h-[260px] flex-col gap-2 overflow-y-auto rounded-[12px] border border-white/[0.06] bg-[#060e1b] p-[14px]"
        >
          {messages.map((m, i) => (
            <div
              key={i}
              className={cn(
                'max-w-[80%] rounded-[12px] px-[13px] py-[9px] text-[13px] leading-normal',
                m.role === 'user'
                  ? 'self-end border border-[#f59e0b]/20 bg-[#f59e0b]/10 text-[#f4f8ff]'
                  : 'self-start border border-white/[0.08] bg-[#0d1b31] text-[#c8d6e8]',
                m.thinking && 'italic text-[#4b6278]',
                m.unavailable && 'text-[#f87171]',
              )}
            >
              {m.content}
            </div>
          ))}
        </div>
        <div className="mt-2.5 flex gap-2">
          <input
            autoComplete="off"
            className={`${FI} flex-1`}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
            placeholder="Ask anything about senior living sales…"
          />
          <DemoButton onClick={submit}>Send</DemoButton>
        </div>
      </Card>

      <Card title="Quick Prompts">
        <div className="flex flex-col gap-1.5">
          {AI_QUICK_PROMPTS.map((p) => (
            <DemoButton key={p} variant="x" className="text-left text-[11px]" onClick={() => void send(p)}>
              {p}
            </DemoButton>
          ))}
        </div>
      </Card>
    </div>
  );
}

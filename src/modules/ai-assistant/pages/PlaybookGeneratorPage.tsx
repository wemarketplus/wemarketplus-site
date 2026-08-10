import { useState } from 'react';
import { Bot, Copy, Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Button, Card, CardContent, Label, Select, Textarea } from '@/shared/ui/core';
import { useGeneratePlaybookMutation } from '@/modules/chat';
import {
  PLAYBOOK_KIND_OPTIONS,
  PLAYBOOK_PLACEHOLDERS,
} from '../constants/playbookConstants';
import type { PlaybookKind } from '../types/aiTypes';

/**
 * AI-generated scripts, SOPs, referral strategies and situation guidance.
 *
 * The route `/integrations/playbooks` previously rendered the Integrations page —
 * the nav item and the `playbook_generator` tier key both existed with nothing
 * behind them. This is that endpoint's screen.
 *
 * It calls the SAME assistant the rest of the product uses (rate limit, daily
 * quota and audit trail included); only the system prompt and a per-kind
 * instruction are new.
 */
export function PlaybookGeneratorPage() {
  const [kind, setKind] = useState<PlaybookKind>('script');
  const [situation, setSituation] = useState('');
  const [context, setContext] = useState('');
  const [result, setResult] = useState<string | null>(null);

  const [generate, { isLoading }] = useGeneratePlaybookMutation();

  const onGenerate = async () => {
    if (!situation.trim()) {
      toast.error('Describe the situation first.');
      return;
    }
    try {
      const response = await generate({
        kind,
        situation: situation.trim(),
        context: context.trim() || undefined,
      }).unwrap();
      // The API answers 200 with `error: true` when the key is missing or the
      // model refused — surfacing that text is more useful than a generic toast.
      // Never substitute something more confident when `text` is absent: an
      // empty response is a real answer ("we produced nothing"), and inventing
      // filler here is exactly what the old client-side AI stub did wrong.
      setResult(
        response.text ??
          'The assistant returned no content. Please try again.',
      );
      if (response.error) {
        toast.error('The assistant could not complete this request.');
      }
    } catch {
      toast.error('Could not generate the playbook. Please try again.');
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">
          Playbook generator
        </h1>
        <p className="text-sm text-muted">
          Scripts, SOPs and referral strategies for a specific situation.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardContent className="space-y-4 px-6 py-6">
            <div>
              <Label htmlFor="pb-kind">What do you need</Label>
              <Select
                id="pb-kind"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value as PlaybookKind);
                  setResult(null);
                }}
              >
                {PLAYBOOK_KIND_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </div>

            <div>
              <Label htmlFor="pb-situation">Situation</Label>
              <Textarea
                id="pb-situation"
                rows={4}
                value={situation}
                onChange={(e) => setSituation(e.target.value)}
                placeholder={PLAYBOOK_PLACEHOLDERS[kind]}
              />
            </div>

            <div>
              <Label htmlFor="pb-context">Background (optional)</Label>
              <Textarea
                id="pb-context"
                rows={3}
                value={context}
                onChange={(e) => setContext(e.target.value)}
                placeholder="What you have already tried, who you know there…"
              />
            </div>

            <Button onClick={onGenerate} disabled={isLoading}>
              <Sparkles className="h-4 w-4" />
              {isLoading ? 'Writing…' : 'Generate'}
            </Button>

            {/* Stated up front, not after the fact. The model is instructed to
                refuse clinical and eligibility questions; saying so here stops a
                rep asking one and treating a hedge as an answer. */}
            <p className="text-[11px] text-muted-soft">
              The assistant does not give clinical advice or decide hospice
              eligibility — that is the physician's determination. Check any
              specifics before using them with an account.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="px-6 py-6">
            {result === null ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <Bot className="h-8 w-8 text-muted-soft" />
                <p className="text-sm text-muted-soft">
                  Your playbook will appear here.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex justify-end">
                  <Button
                    variant="ghost"
                    onClick={() => {
                      void navigator.clipboard.writeText(result);
                      toast.success('Copied');
                    }}
                  >
                    <Copy className="h-4 w-4" /> Copy
                  </Button>
                </div>
                {/* Pre-wrap rather than a markdown renderer: the model returns
                    plain text with numbered steps, and adding a parser for one
                    screen would be a dependency for no gain. */}
                <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground">
                  {result}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

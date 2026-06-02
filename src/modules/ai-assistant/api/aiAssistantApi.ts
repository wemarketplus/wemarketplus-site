// TODO(backend): replace with a real /ai/chat streaming call when the
// model gateway ships. Only this file needs to change at that point.
import { AI_STUB_DELAY_MS } from '../constants/aiPresetsConstants';
import { stubAssistantReply } from '../utils/stubResponse';

export async function sendAiMessage(prompt: string): Promise<string> {
  await new Promise<void>((r) => setTimeout(r, AI_STUB_DELAY_MS));
  return stubAssistantReply(prompt);
}

// Structured legal copy block rendered by LegalShell / LegalBlocks.
export interface LegalBlock {
  heading?: string;
  // Paragraphs; a string[] inside `list` renders as a bullet list.
  paragraphs?: readonly string[];
  list?: readonly string[];
  callout?: { title: string; body: string };
}

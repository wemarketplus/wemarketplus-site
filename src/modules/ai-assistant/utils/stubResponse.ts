// Returns a canned "thinking" response while the AI gateway is pending.
// Lets the UI feel alive without pretending to be real intelligence.
export function stubAssistantReply(userPrompt: string): string {
  const lower = userPrompt.toLowerCase();
  if (lower.includes('cold')) {
    return 'Trinity Senior Living and 2 others are overdue. I queued reminders for tomorrow morning.';
  }
  if (lower.includes('follow-up') || lower.includes('draft')) {
    return 'Here\'s a starter: "Hi [name], following up on our chat — I wanted to share a quick comfort-care brief tailored to your team. Free Tuesday at 10?"';
  }
  if (lower.includes('pending')) {
    return 'For Pending Admission, prioritize POA paperwork first, then schedule the RN intake.';
  }
  return 'Here\'s a draft response — refine before you ship it. (The AI gateway is not wired yet; this is a stub.)';
}

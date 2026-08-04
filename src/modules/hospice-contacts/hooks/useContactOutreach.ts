import { useState } from 'react';
import { toast } from 'sonner';
import { useCreateNoteMutation } from '@/modules/activity';
import type { ActivityType } from '@/shared/constants/activityTypeConstants';
import type { HospiceContactRecord } from '../api/hospiceContactsApi';

/** Which outreach channel a button represents. */
export type OutreachChannel = 'call' | 'text' | 'email';

/**
 * Maps a channel to the canonical activity type the interaction is logged as. These
 * are three of the twelve values in the shared `activity_type_enum`, so a call logged
 * from here is indistinguishable from one logged by hand — which is the point.
 */
const CHANNEL_ACTIVITY: Record<OutreachChannel, ActivityType> = {
  call: 'phone_call',
  text: 'text_sms',
  email: 'email',
};

const CHANNEL_VERB: Record<OutreachChannel, string> = {
  call: 'Called',
  text: 'Texted',
  email: 'Emailed',
};

/**
 * Click-to-call / text / email against a hospice contact, with the interaction logged
 * automatically.
 *
 * WHY THIS EXISTS. The module-flow document's §11.2 lists "click-to-call is a logging
 * shell" as a functional gap: Aircall exists only as an INBOUND webhook log, there is
 * no outbound dialling, and — the part it calls "the whole point" — nothing is logged
 * automatically, so a marketer still had to type "called Dr. Chen at 2pm" by hand.
 *
 * WHAT IS REAL HERE, AND WHAT IS NOT. The dial itself is handed to the operating
 * system via a `tel:` / `sms:` / `mailto:` URI. That is genuine click-to-dial and
 * needs no PBX. It is NOT Aircall placing the call from their platform — that needs
 * Aircall API credentials and a per-tenant agent mapping that do not exist in this
 * codebase, and inventing them would be the same "sold but unbuilt" failure the
 * document is about. When those credentials exist, only `openChannel` changes; the
 * logging below is already correct.
 *
 * The logging is the durable half: every click writes a Note against the contact with
 * the canonical activity type, so the interaction is on the record whether or not the
 * call connected. A failure to log is surfaced, never swallowed — a silent miss here
 * would mean the rep believes the record exists when it does not.
 */
export function useContactOutreach() {
  const [createNote, { isLoading }] = useCreateNoteMutation();
  const [pending, setPending] = useState<string | null>(null);

  const targetFor = (
    contact: HospiceContactRecord,
    channel: OutreachChannel,
  ): string | null => {
    if (channel === 'email') return contact.email;
    // A text prefers the mobile; a voice call takes either, mobile first.
    if (channel === 'text') return contact.mobile;
    return contact.mobile ?? contact.phone;
  };

  const openChannel = (channel: OutreachChannel, target: string) => {
    const uri =
      channel === 'email'
        ? `mailto:${target}`
        : channel === 'text'
          ? `sms:${target}`
          : `tel:${target}`;
    window.open(uri, '_self');
  };

  const reach = async (
    contact: HospiceContactRecord,
    channel: OutreachChannel,
  ) => {
    // doNotContact is enforced server-side for appointment attendees; honour it here
    // too rather than letting a rep dial someone who asked not to be contacted.
    if (contact.doNotContact) {
      toast.error(`${contact.fullName} is marked do-not-contact.`);
      return;
    }
    const target = targetFor(contact, channel);
    if (!target) {
      toast.error(
        channel === 'email'
          ? 'No email address on this contact.'
          : channel === 'text'
            ? 'No mobile number on this contact.'
            : 'No phone number on this contact.',
      );
      return;
    }

    setPending(`${contact.id}:${channel}`);
    try {
      await createNote({
        contactId: contact.id,
        activityType: CHANNEL_ACTIVITY[channel],
        summary: `${CHANNEL_VERB[channel]} ${contact.fullName} (${target}) from the contact record.`,
      }).unwrap();
      openChannel(channel, target);
      toast.success(`${CHANNEL_VERB[channel]} and logged.`);
    } catch {
      // Deliberately do NOT open the channel when logging failed: an unlogged
      // outreach is exactly the gap this closes, so failing loudly is correct.
      toast.error('Could not log that interaction — nothing was dialled.');
    } finally {
      setPending(null);
    }
  };

  return { reach, isLogging: isLoading, pendingKey: pending };
}

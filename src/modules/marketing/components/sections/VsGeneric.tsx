import { SectionHeading } from '../SectionHeading';

// index.html "VS GENERIC" — .compare table contrasting generic CRMs with
// HospiceLink (Feature / Generic CRMs = No / HospiceLink = Yes).
const ROWS: { feature: string; gold?: boolean }[] = [
  { feature: 'Built for hospice referral workflows' },
  { feature: '14-day cold source alerts' },
  { feature: 'Inquiry to Admitted pipeline built-in' },
  { feature: 'EVV & GPS mileage tracking' },
  { feature: 'HIPAA-ready with BAA included' },
  { feature: 'Works on day one, no configuration' },
  { feature: 'AI Referral Triage & Scoring', gold: true },
  { feature: 'Revenue Intelligence dashboard', gold: true },
  { feature: 'Aircall — Call, Text & Email from CRM', gold: true },
];

export function VsGeneric() {
  return (
    <section className="mx-auto max-w-[860px] px-7 py-12">
      <SectionHeading
        kicker="Why HospiceLink"
        tone="azure"
        title="Generic CRMs Were Not Built for This"
        body="HubSpot and Salesforce are built for generic sales pipelines. Hospice requires referral relationship management, census workflows, and HIPAA compliance out of the box."
      />
      <div className="overflow-x-auto rounded-[16px] border border-white/[0.08] bg-white/[0.03]">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr className="bg-white/[0.02]">
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-left text-[11px] font-bold uppercase tracking-[0.07em] text-faint">
                Feature
              </th>
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-center text-[11px] font-bold uppercase tracking-[0.07em] text-[#f87171]">
                Generic CRMs
              </th>
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-center text-[11px] font-bold uppercase tracking-[0.07em] text-sage">
                HospiceLink
              </th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r, i) => (
              <tr key={r.feature}>
                <td
                  className={`px-[18px] py-[10px] text-left font-semibold text-foreground ${
                    i !== ROWS.length - 1 ? 'border-b border-white/[0.04]' : ''
                  }`}
                >
                  {r.feature}
                </td>
                <td
                  className={`px-[18px] py-[10px] text-center text-white/[0.15] ${
                    i !== ROWS.length - 1 ? 'border-b border-white/[0.04]' : ''
                  }`}
                >
                  No
                </td>
                <td
                  className={`px-[18px] py-[10px] text-center font-bold text-sage ${
                    r.gold ? 'text-[11px]' : ''
                  } ${i !== ROWS.length - 1 ? 'border-b border-white/[0.04]' : ''}`}
                >
                  {r.gold ? 'Yes — Gold' : 'Yes'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function ProductCards() {
  return (
    <div style={{ padding: '56px 20px' }}>
      <div style={{ maxWidth: 960, margin: '0 auto' }}>
        <div style={{ display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap' }}>

          {/* HospiceLink CRM Card */}
          <div
            style={{
              flex: '1 1 0%',
              minWidth: 240,
              maxWidth: 440,
              background: 'linear-gradient(135deg,rgba(79,200,122,0.09),rgba(79,200,122,0.015))',
              borderStyle: 'solid',
              borderWidth: 1,
              borderColor: 'rgba(79,200,122,.16)',
              borderRadius: 18,
              padding: 26,
              cursor: 'pointer',
              transition:
                'border-color 0.3s ease, transform 0.3s cubic-bezier(0.22,1,0.36,1)',
              position: 'relative',
              overflow: 'hidden',
              transform: 'translateY(0px)',
            }}
            onClick={() => document.getElementById('hospicelink')?.scrollIntoView({ behavior: 'smooth' })}
            onMouseOver={(e) => {
              (e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(79,200,122,.45)';
              (e.currentTarget as HTMLDivElement).style.transform = 'translateY(-4px)';
            }}
            onMouseOut={(e) => {
              (e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(79,200,122,.16)';
              (e.currentTarget as HTMLDivElement).style.transform = 'translateY(0)';
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div className="text-sage" style={{ fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 8 }}>
                  Solutions for Hospice Teams
                </div>
                <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-1)', letterSpacing: '-.02em', marginBottom: 6 }}>
                  HospiceLink CRM
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  Track referrals, close admits, manage outreach — built exclusively for hospice marketers.
                </div>
              </div>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(79,200,122,.1)', border: '1px solid rgba(79,200,122,.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginLeft: 12 }}>
                <svg viewBox="0 0 24 24" style={{ width: 20, height: 20, stroke: '#4fc87a', fill: 'none', strokeWidth: 1.8, strokeLinecap: 'round' }}>
                  <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                </svg>
              </div>
            </div>
            <div className="text-sage" style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 700 }}>
              View Hospice Plans
              <svg viewBox="0 0 24 24" style={{ width: 12, height: 12, stroke: 'currentColor', fill: 'none', strokeWidth: 2.5 }}>
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </div>
          </div>

          {/* CommunityLink CRM Card */}
          <div
            style={{
              flex: '1 1 0%',
              minWidth: 240,
              maxWidth: 440,
              background: 'linear-gradient(135deg,rgba(245,158,11,0.08),rgba(245,158,11,0.015))',
              border: '1px solid rgba(245,158,11,0.16)',
              borderRadius: 18,
              padding: 26,
              cursor: 'pointer',
              transition:
                'border-color 0.3s ease, transform 0.3s cubic-bezier(0.22,1,0.36,1)',
              position: 'relative',
              overflow: 'hidden',
              transform: 'translateY(0px)',
            }}
            onClick={() => document.getElementById('communitylink')?.scrollIntoView({ behavior: 'smooth' })}
            onMouseOver={(e) => {
              (e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(245,158,11,.45)';
              (e.currentTarget as HTMLDivElement).style.transform = 'translateY(-4px)';
            }}
            onMouseOut={(e) => {
              (e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(245,158,11,.16)';
              (e.currentTarget as HTMLDivElement).style.transform = 'translateY(0)';
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.1em', color: '#f59e0b', marginBottom: 8 }}>
                  Solutions for Senior Living Teams
                </div>
                <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-1)', letterSpacing: '-.02em', marginBottom: 6 }}>
                  CommunityLink CRM
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  Manage leads, occupancy, referrals &amp; operations — built for senior living &amp; assisted living communities.
                </div>
              </div>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(245,158,11,.1)', border: '1px solid rgba(245,158,11,.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginLeft: 12 }}>
                <svg viewBox="0 0 24 24" style={{ width: 20, height: 20, stroke: '#f59e0b', fill: 'none', strokeWidth: 1.8, strokeLinecap: 'round' }}>
                  <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
                  <polyline points="9 22 9 12 15 12 15 22" />
                </svg>
              </div>
            </div>
            <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 700, color: '#f59e0b' }}>
              View Senior Living Plans
              <svg viewBox="0 0 24 24" style={{ width: 12, height: 12, stroke: 'currentColor', fill: 'none', strokeWidth: 2.5 }}>
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

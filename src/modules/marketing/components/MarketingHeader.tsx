import { Phone } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';
import { BrandLogo } from './BrandLogo';

// Top nav — mirrors the live wemarketplus.com nav: logo, HospiceLink /
// CommunityLink / FAQ / Security / Contact links, phone, Log In pill.
export function MarketingHeader() {
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-bg/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link to="/" aria-label="We Market Plus home" className="flex items-center">
          <BrandLogo />
        </Link>

        <nav className="hidden items-center gap-7 text-[14px] font-semibold text-muted md:flex">
          <Link to="/pricing" className="hover:text-foreground">
            HospiceLink
          </Link>
          <Link to="/communitylink" className="hover:text-foreground">
            CommunityLink
          </Link>
          <a href="#faq" className="hover:text-foreground">
            FAQ
          </a>
          <a href="#security" className="hover:text-foreground">
            Security
          </a>
          <a href="#contact" className="hover:text-foreground">
            Contact
          </a>
          <a
            href="tel:+19725550100"
            className="inline-flex items-center gap-1.5 text-[13px] text-muted-soft hover:text-foreground"
          >
            <Phone className="h-3.5 w-3.5" /> (972) 555-0100
          </a>
        </nav>

        <Link to="/login">
          <Button size="sm" className="bg-sage text-[#06080e]">
            Log In
          </Button>
        </Link>
      </div>
    </header>
  );
}

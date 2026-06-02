// Reusable Tailwind class strings that reproduce the reference stylesheet
// (communitylinkpro-demo.html <style>) 1:1. Static values only — keeps every
// demo component pixel-faithful without repeating arbitrary-value soup.

// .card / .card-hd / .card-t
export const CARD = 'mb-[14px] rounded-[14px] border border-white/[0.06] bg-[#0a1628] p-[18px]';
export const CARD_HEAD = 'mb-[14px] flex items-center justify-between';
export const CARD_TITLE = 'text-[13px] font-extrabold text-[#f4f8ff]';

// .stat / .sl / .sv / .ss (+ tone colors .sg/.sr/.sa)
export const STAT = 'cursor-pointer rounded-[12px] border border-white/[0.06] bg-[#0a1628] px-4 py-[14px] transition-colors hover:border-[#f59e0b]/30';
export const STAT_LABEL = 'mb-1.5 text-[10px] font-bold uppercase tracking-[0.06em] text-[#4b6278]';
export const STAT_VALUE = 'text-[26px] font-black leading-none text-[#f4f8ff]';
export const STAT_SUB = 'mt-[3px] text-[10px] text-[#6b7fa3]';

// .fi / .flb / .fl / .fg / .fw
export const FI = 'w-full rounded-[8px] border border-white/10 bg-[#0d1f38] px-[11px] py-2 text-[13px] text-[#f4f8ff] outline-none transition-colors focus:border-[#f59e0b]';
export const FLB = 'text-[11px] font-bold text-[#4b6278]';
export const FL = 'flex flex-col gap-1';
export const FG = 'mb-3 grid grid-cols-2 gap-3';
export const FW = 'col-span-full';

// .btn variants
export const BTN_BASE = 'cursor-pointer rounded-full border-none px-[14px] py-[7px] text-[12px] font-bold transition-opacity hover:opacity-85 disabled:opacity-50';
export const BTN_SM = 'px-[11px] py-[5px] text-[11px]';
export const BTN_A = 'bg-gradient-to-br from-[#f59e0b] to-[#d97706] text-[#06080e]';
export const BTN_G = 'bg-gradient-to-br from-[#4fc87a] to-[#22a855] text-[#06080e]';
export const BTN_X = 'border border-white/[0.08] bg-white/[0.06] text-[#8ba4c4]';
export const BTN_R = 'border border-[#f87171]/20 bg-[#f87171]/10 text-[#f87171]';

// .tbl / th / td
export const TBL = 'w-full border-collapse text-[12px]';
export const TH = 'border-b border-white/[0.05] px-2.5 py-2 text-left text-[10px] font-extrabold uppercase tracking-[0.06em] text-[#1e3a5f]';
export const TD = 'border-b border-white/[0.04] px-2.5 py-2.5 align-middle text-[#c8d6e8]';

// Shared tone text colors.
export const TEXT_GREEN = 'text-[#4fc87a]';
export const TEXT_RED = 'text-[#f87171]';
export const TEXT_AMBER = 'text-[#f59e0b]';

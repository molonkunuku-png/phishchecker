import { type ReactNode } from 'react';

type IconName =
  | 'shield'
  | 'shield-check'
  | 'lock'
  | 'download'
  | 'copy'
  | 'printer'
  | 'arrow-right'
  | 'x'
  | 'menu'
  | 'clock'
  | 'layout-dashboard'
  | 'sparkles'
  | 'book-open'
  | 'code'
  | 'info'
  | 'activity'
  | 'sun'
  | 'moon'
  | 'refresh'
  | 'chevron-down'
  | 'mail'
  | 'check-circle'
  | 'smartphone'
  | 'search'
  | 'zap'
  | 'globe'
  | 'alert-triangle'
  | 'bar-chart'
  | 'image'
  | 'users';

const icons: Record<IconName, (props: { size?: number; className?: string }) => ReactNode> = {
  'shield': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" className={className} aria-hidden="true">
      <path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="currentColor" opacity="0.9"/>
      <path d="M24 34l6 6 10-12" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  ),
  'shield-check': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" className={className} aria-hidden="true">
      <path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="currentColor" opacity="0.9"/>
      <path d="M24 34l6 6 10-12" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  ),
  'lock': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="12" y="26" width="40" height="22" rx="3" />
      <path d="M22 26V18h20v12" />
      <circle cx="32" cy="37" r="2" fill="currentColor" stroke="none" />
    </svg>
  ),
  'download': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M32 12v28" />
      <path d="M22 22l10 10 10-10" />
      <path d="M12 36h40v14H12z" />
    </svg>
  ),
  'copy': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M48 14c6 6 10 13 10 22s-4 16-10 22c-6-6-10-13-10-22s4-16 10-22z" />
      <path d="M16 14c6 6 10 13 10 22s-4 16-10 22c-6-6-10-13-10-22s4-16 10-22z" />
      <path d="M26 26h22v22H26z" />
    </svg>
  ),
  'printer': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 38v10h40v-10" />
      <path d="M20 38V22h24v16" />
      <rect x="12" y="26" width="40" height="18" rx="2" />
      <path d="M22 26V14h20v12" />
    </svg>
  ),
  'arrow-right': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 32h40" />
      <path d="M36 20l10 12-10 12" />
    </svg>
  ),
  'x': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="6" strokeLinecap="round" className={className} aria-hidden="true">
      <path d="M16 16l32 32M48 16l-32 32" />
    </svg>
  ),
  'menu': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="6" strokeLinecap="round" className={className} aria-hidden="true">
      <path d="M12 20h40M12 32h40M12 44h40" />
    </svg>
  ),
  'clock': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="32" cy="32" r="24" />
      <path d="M32 16v16l10 6" />
    </svg>
  ),
  'layout-dashboard': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="8" y="8" width="24" height="24" rx="3" />
      <rect x="32" y="8" width="24" height="24" rx="3" />
      <rect x="8" y="32" width="24" height="24" rx="3" />
      <rect x="32" y="32" width="24" height="24" rx="3" />
    </svg>
  ),
  'sparkles': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M28 8l4 16 16 4-16 4-4 16-4-16-16-4 16-4 4-16z" />
    </svg>
  ),
  'book-open': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 12c0 16 20 20 20 36" />
      <path d="M52 12c0 16-20 20-20 36" />
      <path d="M12 12h40" />
    </svg>
  ),
  'code': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M20 20l-12 24 12 24" />
      <path d="M44 20l12 24-12 24" />
      <path d="M36 16l-16 32" />
    </svg>
  ),
  'info': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="32" cy="32" r="24" />
      <path d="M32 28v12" />
      <circle cx="32" cy="22" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  'activity': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 32h8l6-16 8 32 6-16 10 24h8" />
    </svg>
  ),
  'sun': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="32" cy="32" r="10" />
      <path d="M32 8v8M32 48v8M8 32h8M48 32h8M15 15l6 6M43 43l6 6M15 49l6-6M43 21l6-6" />
    </svg>
  ),
  'moon': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M40 16c-12 8-20 20-16 36 8-12 20-20 36-16-12-8-20-20-16-36-8 12-20 20-36 16z" />
    </svg>
  ),
  'refresh': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 32c0-12 10-20 20-20h6" />
      <path d="M52 32c0 12-10 20-20 20h-6" />
      <path d="M44 12v8h8" />
      <path d="M20 44v-8h-8" />
      <path d="M52 12l-4 4-8-8" />
      <path d="M12 52l4-4 8 8" />
    </svg>
  ),
  'chevron-down': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M16 26l16 16 16-16" />
    </svg>
  ),
  'mail': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="8" y="16" width="48" height="32" rx="3" />
      <path d="M8 16l24 20 24-20" />
    </svg>
  ),
  'check-circle': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="32" cy="32" r="24" />
      <path d="M20 32l8 8 14-16" />
    </svg>
  ),
  'smartphone': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="16" y="6" width="32" height="52" rx="4" />
      <path d="M32 46v4" />
    </svg>
  ),
  'search': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="28" cy="28" r="18" />
      <path d="M42 42l14 14" />
    </svg>
  ),
  'zap': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M36 6L10 36h20L28 58l26-30H34l8-22z" />
    </svg>
  ),
  'globe': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="32" cy="32" r="24" />
      <path d="M32 8v48M8 32h48M16 16c8 8 8 24 0 32M48 16c-8 8-8 24 0 32" />
    </svg>
  ),
  'alert-triangle': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M32 14l20 36H12l20-36z" />
      <path d="M32 22v14" />
      <circle cx="32" cy="46" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  'bar-chart': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="12" y="24" width="12" height="28" rx="2" />
      <rect x="26" y="14" width="12" height="38" rx="2" />
      <rect x="40" y="32" width="12" height="20" rx="2" />
    </svg>
  ),
  'image': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect x="8" y="14" width="48" height="36" rx="3" />
      <circle cx="22" cy="28" r="5" />
      <path d="M8 42l18-14 12 10 14-8v12H8z" />
    </svg>
  ),
  'users': ({ size = 24, className = '' }) => (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <circle cx="24" cy="22" r="10" />
      <path d="M4 54c0-11 9-18 20-18s20 7 20 18" />
      <circle cx="44" cy="22" r="6" />
      <path d="M52 42c2-6 6-10 12-10" />
    </svg>
  ),
};

export function Icon({ name, size = 24, className = '' }: { name: IconName; size?: number; className?: string }) {
  const renderer = icons[name];
  if (!renderer) return null;
  return <>{renderer({ size, className })}</>;
}

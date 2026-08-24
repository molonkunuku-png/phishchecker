# PhishChecker — 50+ Item Design & Experience Audit / Roadmap

## Current State Snapshot

### Fonts In Use
| Role | Stack | Notes |
|------|-------|-------|
| Body / Sans | Inter, ui-sans-serif, system-ui | Clean, but very common for SaaS |
| Display / Headings | Source Serif 4, Lora, Georgia, serif | Warm, authoritative |
| Mono | ui-monospace, SFMono, Menlo | Data, URLs |

**Issue:** Source Serif 4 is a solid serif but lacks the "shield / protection" character a phishing tool needs. Inter is generic. No variable font tuning, no optical size variants.

### Logo In Use
- Shield mark: 3-layer stacked shield paths, gold gradient (#D4AF37 → #bfa030), dark navy (#0D1B2A) checkmark
- Logomark file: `frontend/public/static/icons/logomark.svg`
- Wordmark: plain text "PhishChecker" in nav, no ligature / custom treatment
- Favicon: same shield at 192/512px

**Issue:** Logo exists but isn't leveraged as a design system anchor. No monochrome variant, no icon-only usage rules, no dark/light inversion rules.

### Current Color Tokens
| Token | Dark | Light |
|-------|------|-------|
| --bg-canvas | #0A0F1C | #F8FAFC |
| --bg-surface | #111827 | #FFFFFF |
| --bg-surface-raised | #1a2332 | #F1F5F9 |
| --gold-500 (primary) | #3B62F6 | #2563EB |
| --gold-600 | #2563EB | #1D4ED8 |
| --risk-safe | #0B8560 (teal) | #059669 |
| --risk-caution | #D97706 (amber) | #D97706 |
| --risk-danger | #DC2626 (red) | #DC2626 |

**Issue:** "gold" token maps to electric blue — semantically confusing. Gold literal (#D4AF37) only appears in inline SVG gradients.

---

## 50+ Planning Items

### A. TYPOGRAPHY & FONT SYSTEM (8 items)

A1. Replace Source Serif 4 with a more protective/security-native display face
    - Candidates: DM Serif Display, Fraunces, or Literata
    - Rationale: Source Serif 4 feels editorial/literary; a serif with more geometric weight reads as "guard/protection"
    - Weight range: 400 (body display) → 700 (hero headline)

A2. Pair display serif with a tighter sans for subheads
    - Use Inter at 600/700 weight for section labels, captions
    - Set --text-label role at 0.75rem, 700wt, 0.1em tracking uppercase

A3. Establish a strict type scale with named roles
    - --text-display: 2.5rem (hero only)
    - --text-h1: 2rem
    - --text-h2: 1.5rem
    - --text-h3: 1.15rem
    - --text-body: 1.0625rem (current, keep)
    - --text-caption: 0.8rem
    - --text-overline: 0.65rem (NEW — for badges/labels)
    All derived from modular scale 1.25 (major third).

A4. Add font-feature-settings for Inter
    - 'cv02', 'cv03' (Inter-specific alternates for 0/1/O disambiguation)
    - 'tnum' on all score/stat numerals

A5. Set line-height by role, not globally
    - Headings: 1.15
    - Body: 1.6 (current, correct)
    - Captions/overline: 1.4
    - Data cells: 1.3

A6. Introduce a data-optimized mono variant for URLs/scores
    - Add --font-mono-data: "JetBrains Mono", ui-monospace, Menlo
    - Use for score numerals, URLs, JSON blocks

A7. Add font-display: swap to @import rules
    - Prevent FOIT on slow connections

A8. Tighten letter-spacing on headings
    - h1: -0.03em (current, good)
    - h2: -0.02em
    - h3: -0.01em
    - body/caption: 0 (default)

### B. LOGO & BRAND IDENTITY (6 items)

B1. Create a monochrome logo variant for light mode nav
    - Current shield uses #0D1B2A checkmark which disappears on dark bg
    - Light mode needs inverted: white shield fill, dark checkmark

B2. Add icon-only (logomark) usage rules
    - Favicon: shield only, no text
    - Nav collapsed: shield only
    - PWA manifest: ensure theme_color matches brand

B3. Introduce a subtle brand-watermark / background pattern
    - Repeating shield outline at 3% opacity as bg texture on hero
    - Reinforces brand without competing with content

B4. Define logo minimum-clear-space
    - Equal to the height of the shield's inner checkmark on all sides

B5. Add wordmark ligature / custom kerning option
    - Option: use Inter with custom letter-spacing on "PhishChecker" text
    - --brand-text-spacing: -0.02em

B6. Create a horizontal lockup SVG
    - Shield (26px) + wordmark for nav-brand
    - Reduces inline SVG bloat in App.tsx

### C. BUTTON DESIGN & INTERACTION (10 items)

C1. Standardize all button inline styles into CSS classes
    - Currently ~30 buttons have inline style={{...}} overrides
    - Create: .pc-btn-xs, .pc-btn-sm, .pc-btn, .pc-btn-lg tiers
    - Create: .pc-btn-danger (for retry/flag actions)

C2. Add ripple / press feedback animation
    - ::after pseudo-element with scale + opacity on :active
    - 150ms ease-out, ripple 60% of button size
    - Must respect prefers-reduced-motion

C3. Add focus-visible ring to all buttons (some are missing)
    - Audit: hamburger, ghost nav links, export menu items
    - All need ring via :focus-visible or .pc-btn:focus-visible

C4. Icon-button size discipline
    - All icon-only buttons must be exactly 44×44px
    - Current print button: padding '14px 14px' — OK but add explicit width/height

C5. Button loading state with shimmer, not just spinner
    - Extend .pc-spinner into .pc-btn-loading that applies shimmer across full button face
    - Disable pointer events during load

C6. Export dropdown: add keyboard trap and Escape-to-close
    - Current dropdown is mouse-only
    - Add onKeyDown handler + first/last focus management

C7. Primary button gradient: unify across all instances
    - Currently inline styles override box-shadow on copy button
    - Move gradient + shadow fully to .pc-btn-primary

C8. Add "danger" variant for destructive actions
    - .pc-btn-danger: red bg, white text, red shadow
    - Use for "Clear history" / "Delete" if added

C9. Button text overflow handling
    - Add .pc-btn { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    - For narrow mobile: allow wrap with .pc-btn-wrap modifier

C10. Hover lift on cards/panels that contain buttons
    - .pc-panel:hover → translateY(-2px) + shadow increase
    - Reinforces clickability of card-as-button (screenshot, QR tool cards)

### D. ANIMATION & MOTION WORKFLOW (10 items)

D1. Orchestrate scan result reveal as a sequence, not instant
    - Step 1 (0ms): gauge animates from 0 to score
    - Step 2 (300ms): verdict badge fades in
    - Step 3 (500ms): risk bar fills
    - Step 4 (700ms): detail cards stagger in
    - Use CSS animation-delay or a lightweight timeline

D2. Gauge animation: start from 0 on every new result
    - Current: gauge renders final state immediately if result changes fast
    - Fix: reset stroke-dasharray to 0, then animate to target on result change

D3. Nav shadow transition: smoother + shorter
    - Current: 250ms box-shadow transition
    - Change to 180ms, add slight background-color transition for perceived speed

D4. Add enter/exit animation for sections
    - When showHistory toggles: section slides down (max-height + opacity)
    - When alert dismisses: slide up + fade out before removing from DOM

D5. Stagger children animation on hero load
    - Badge → h1 → p → form → tools grid: 80ms stagger
    - Creates a choreographed "unfolding" first impression

D6. Score bar fill animation
    - Current: width transition 420ms — good
    - Add: animate from 0% width on mount, not from previous score

D7. Batch results: staggered reveal
    - Each result card: 60ms delay increment
    - Gives rhythm to long batch outputs

D8. Reduce motion: audit all animated properties
    - Current: only .pc-animate-in is killed
    - Expand: gauge transition, bar width transition, nav shadow should also respect reduced motion

D9. Add a "scan pulse" on the shield logo while loading
    - Subtle glow pulse on the shield SVG during scan
    - Reinforces that something is happening

D10. Button hover: add subtle glow on primary
    - Current: translateY(-1px) + shadow — good
    - Add: box-shadow with gold tint to match brand feel

### E. COLOR & SHADE SYSTEM (8 items)

E1. Fix "gold" semantic confusion
    - Rename --gold tokens to --brand-* (or --accent-*)
    - --gold → --brand-primary
    - --gold-500 → --brand-500
    - --gold-600 → --brand-600
    - --gold-muted → --brand-muted
    - --border-gold → --border-brand
    - Add comment: "Named 'brand' not 'gold' — gold literal is #D4AF37 for logo only"

E2. Introduce a true gold accent for shield/logo consistency
    - Add --gold: #D4AF37 (actual gold)
    - --gold-300: #E8CC6E
    - --gold-600: #A88B2A
    - Use sparingly: logo, special badges, premium feel moments

E3. Expand surface palette to 5 levels
    - --bg-canvas (deepest)
    - --bg-surface
    - --bg-surface-raised (current, keep)
    - --bg-surface-hover (NEW: slightly lighter for hover)
    - --bg-surface-overlay (NEW: for dropdowns/modals)

E4. Add semantic color aliases
    - --color-info: #3B62F6 (current electric blue)
    - --color-success: --risk-safe
    - --color-warning: --risk-caution
    - --color-error: --risk-danger
    - Makes JSX color references more readable

E5. Light mode: verify all contrast ratios
    - Current dark mode: verified 7.54:1+
    - Light mode tokens: #0F172A on #F8FAFC = 14.7:1 ✓
    - --text-secondary (#334155) on --bg-surface (#FFFFFF) = 7.2:1 ✓
    - --gold-500 (#2563EB) on --bg-surface (#FFFFFF) = 4.6:1 ✓ (passes AA)

E6. Add a subtle gradient to the hero panel
    - Current: linear-gradient(180deg, surface → midnight) — functional
    - Refine: add a very subtle brand tint at the bottom
    - linear-gradient(180deg, var(--bg-surface) 0%, var(--bg-midnight) 70%, color-mix(in srgb, var(--brand-500) 3%, var(--bg-midnight)) 100%)

E7. Risk bar: add gradient, not flat color
    - High risk: linear-gradient(90deg, var(--risk-danger), #F87171)
    - Caution: linear-gradient(90deg, var(--risk-caution), #FBBF24)
    - Safe: linear-gradient(90deg, var(--risk-safe), #34D399)

E8. Define animation-safe color usage
    - Never animate background-color (expensive repaint)
    - Animate opacity, transform, filter only
    - For loading shimmer: animate background-position on gradient

### F. ICON SYSTEM (6 items)

F1. Replace emoji icons with SVG equivalents
    - 📱, 📧, 🔐, ✅, ⚠, 🛡️, 🕰️, 🔎 in awareness/about/features sections
    - Use Lucide/Heroicons SVGs inline or a tiny icon component
    - Emojis render inconsistently across platforms and break brand tone

F2. Create an Icon component with 24px and 16px sizes
    - src/components/Icon.tsx
    - Props: name, size, className
    - Inline SVG sprite or direct import from lucide-react

F3. Standardize existing inline SVGs
    - Shield, lock, download, copy, printer, shield-check, arrow-right
    - All should use currentColor, no hardcoded stroke="#0D1B2A"
    - Checkmark in shield: use currentColor or var(--text-inverse)

F4. Add icons to nav links (optional, for faster scanning)
    - History: clock
    - Dashboard: layout-dashboard
    - Features: sparkles
    - Awareness: book-open
    - API: code
    - About: info
    - Status: activity
    - Theme: sun/moon
    - Keep icons small (14px), right of label

F5. Replace Unicode hamburger (☰) and close (×) with SVG icons
    - More consistent sizing, better animation hook

F6. Add aria-hidden="true" + aria-label discipline
    - Audit all inline SVGs for proper labeling
    - Decorative: aria-hidden="true"
    - Meaningful: aria-label or <title>

### G. COMPONENT POLISH (8 items)

G1. Results section: add a "scan timestamp" micro-label
    - "Scanned X seconds ago" below the gauge
    - Gives temporal context to stale results

G2. History panel: add swipe-to-reveal actions on mobile
    - Swipe left on history item → reveal Delete button
    - Native-feeling on iOS/Android

G3. Score breakdown: convert to a mini bar chart
    - Each penalty bar visually proportional
    - Easier to scan than a table of numbers

G4. Empty state: add a subtle shield animation
    - Slow floating / breathing on the shield icon
    - Draws eye without being distracting

G5. Error toast: add slide-down animation + auto-dismiss
    - Current: fixed position, static
    - Add: transform translateY(-100%) → translateY(0) on mount
    - Auto-dismiss after 8s with progress bar

G6. Loading state: add progress text
    - "Checking headers..." → "Checking SSL..." → "Analyzing..."
    - Reduces perceived wait time

G7. Add a "confidence meter" alongside the gauge
    - Low score = high confidence (big red gauge)
    - High score = lower confidence gauge (yellow/uncertain)
    - Visual: gauge border color shifts from solid to dashed at lower confidence

G8. Community flag card: redesign to match panel system
    - Currently uses prompt/alert (blocking UX)
    - Replace with inline expandable form
    - Better UX, less jarring

### H. LAYOUT & SPACING (4 items)

H1. Reduce inline style duplication via CSS utility classes
    - .pc-max-width, .pc-center, .pc-stack, .pc-gap-sm/med/lg
    - App.tsx has 200+ inline style objects — most are repeated spacing patterns

H2. Add consistent section vertical rhythm
    - Every section: padding-block = var(--sp-7) (3rem)
    - Current sections vary: 1.6em, 2em, 2.5em
    - Enforce via .pc-section + .pc-section-lg

H3. Card hover lift: add to all .pc-panel instances
    - transform: translateY(-2px)
    - box-shadow increase
    - 200ms ease
    - Gives tactile feel to interactive cards (screenshot, QR, flag, scheduled)

H4. Mobile: add safe-area-inset padding for notched phones
    - padding-bottom: env(safe-area-inset-bottom) on footer
    - padding-top: env(safe-area-inset-top) on nav

### I. ACCESSIBILITY (4 items)

I1. Verify all interactive elements have focus-visible styles
    - Current: :focus-visible on root + nav links
    - Missing: some ghost buttons, hamburger, export dropdown items

I2. Add skip-to-content link that's always visible on focus
    - Current: hidden off-screen until :focus — correct
    - Verify it actually appears and jumps to #main

I3. Ensure color is never the only signal
    - Risk badges: already have text labels ✓
    - Gauge: has numeric score ✓
    - Add: aria-label on gauge: "Risk score: X out of 100, Y risk level"

I4. Add reduced-motion: animate support to gauge + bars
    - Current: only .pc-animate-in has prefers-reduced-motion
    - Extend to gauge transition, score bar, risk bar

### J. PERFORMANCE & TECHNICAL DEBT (4 items)

J1. Move inline styles to CSS classes (the big cleanup)
    - App.tsx inline styles: ~200 instances
    - Target: reduce inline styles by 70% in first pass
    - Benefits: smaller JS bundle, easier theming, no style duplication

J2. Replace CSS @import with <link> in index.html
    - Tailwind @import triggers a separate fetch per file
    - Move to preload in index.html <head>

J3. Add font-preload for critical fonts
    - <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:wght@400;600;700&display=swap">

J4. SVG optimization pass
    - logomark.svg: 771 bytes — good
    - Inline SVGs in App.tsx: dedupe repeated shield + checkmark paths
    - Create src/lib/icons/shield.tsx component, import everywhere

---

## Priority Execution Order

### Batch 1 — Foundation (no visual break risk)
- A3 (type scale roles), E1 (fix gold naming), E4 (semantic aliases)
- F1 (emoji → SVG plan), H1 (CSS utility classes)

### Batch 2 — Brand Cohesion
- A1 (display font swap), B1 (logo variants), B6 (lockup SVG)
- E2 (true gold tokens), E6 (hero gradient)

### Batch 3 — Component Polish
- C1 (button class standardization), C2 (ripple), F2 (Icon component)
- G1-G4 (results/history/empty polish)

### Batch 4 — Motion & Animation
- D1 (orchestrated reveal), D2 (gauge reset), D5 (stagger)
- D9 (scan pulse), G5 (toast animation)

### Batch 5 — Accessibility & Performance
- I1-I4 (a11y audit), J1-J4 (debt cleanup)
- SVG optimization, font preload

---

## Font Recommendation Deep-Dive

### Current: Source Serif 4 + Inter
Pros: readable, professional, widely available
Cons: generic, doesn't signal "security/protection", Source Serif 4 optical sizes limited

### Recommended: Fraunces + Inter
- Fraunces: variable serif with "wonk" axis, has a guardian/old-school-security feel
- Optical sizes: 9pt–72pt
- Variable font = single request, weight + wonk axes
- Google Fonts: yes, fully free

### Alternative: DM Serif Display + Inter
- DM Serif Display: only 400i, very clean, strong contrast strokes
- Lighter weight = faster load
- Less distinctive than Fraunces but safer

### Recommendation: Fraunces (display) + Inter (body/sans) + JetBrains Mono (data)
- Rationale: Fraunces has character that says "heritage, trust, protection"
- Inter for body = same as current, no migration pain
- JetBrains Mono for scores/URLs = crisp, designed for data

---

## Animation Principles for PhishChecker

1. **Purpose over decoration**: Every animation should communicate state change
   - Gauge fill = scan progress + risk level
   - Staggered reveal = data is being "unpacked"
   - Button press = tactile confirmation

2. **Speed matters**: Security users want speed
   - Micro-interactions: 120-180ms
   - Section reveals: 300-420ms
   - Orchestrated sequence: complete in < 1s total

3. **Respect reduced motion**: Always
   - Replace with opacity fade or instant switch
   - Never disable content — only change motion

4. **Loading ≠ decoration**: Only animate loading states
   - Spinner/shimmer: loading only
   - No ambient floating/breathing on idle elements

---

## Button Design Spec

### Hierarchy
| Tier | Class | Use | Visual |
|------|-------|-----|--------|
| Primary | .pc-btn-primary | Scan, main actions | Brand gradient, white text, shadow |
| Secondary | .pc-btn-secondary | Export, view, filter | Bordered, hover fill |
| Ghost | .pc-btn-ghost | Nav, filters, dismiss | Transparent, hover tint |
| Danger | .pc-btn-danger | Delete, clear | Red bg, white text |
| Icon | .pc-btn-icon | Print, copy | 44×44, ghost bg |

### States
- Default → Hover: translateY(-1px), shadow increase, 180ms
- Hover → Active: translateY(0), scale(0.98), 100ms
- Disabled: opacity 0.5, cursor not-allowed, no hover/active
- Focus-visible: 2px outline, 3px offset, brand color

### Sizing
- Default: 14px vertical, 20px horizontal, --r-lg radius
- .pc-btn-sm: 10px v, 14px h, --r-md radius, 0.85em font
- .pc-btn-lg: 18px v, 28px h, --r-xl radius, 1.1em font

---

## Shade / Elevation System

### Current: 3 surface levels
### Proposed: 5 levels

```
--bg-canvas        → deepest background (page)
--bg-surface       → section/card background
--bg-surface-raised→ elevated card, input bg
--bg-surface-hover → hover state for cards/rows
--bg-surface-overlay→ dropdowns, modals, menus
```

Each step: +8-12% lightness in dark mode, -2-4% in light mode.
Elevation communicated via background + border + shadow combo.

---

## Anti-Patterns to Avoid

1. Gradient buttons everywhere — only primary CTA gets gradient
2. Emoji icons in feature cards — use SVGs
3. Multiple animation timings — pick 3: 150ms (micro), 300ms (reveal), 500ms (orchestrated)
4. Inline styles for colors — always use tokens
5. "Gold" misnamed tokens — fix before expanding
6. Animated width/height — use transform/opacity only
7. Hover-only interactions — always have click/tap fallback
8. Generic Inter + generic serif — Fraunces adds identity
9. No loading skeleton for batch scans — add shimmer rows
10. Fixed toast with no exit animation — add slide + fade

---

## Quick Wins (< 30 min each, no build risk)

1. Add font-feature-settings to @theme block
2. Replace emoji with aria-hidden spans (visual same, a11y better)
3. Add .pc-btn-danger class (no consumers yet, but ready)
4. Add --text-overline role token
5. Add --color-info semantic alias
6. Add .pc-surface-hover + .pc-surface-overlay tokens
7. Add prefers-reduced-motion to gauge/bar transitions
8. Add ripple CSS to .pc-btn (progressive enhancement)
9. Replace ☰ hamburger with inline SVG
10. Add loading-progress text state

---

*Generated: 2026-08-24 | Project: PhishChecker | Stack: React + Vite + Tailwind + Flask*

# Browser Compatibility

PhishChecker targets modern evergreen browsers.

| Browser | Supported | Notes |
|---------|-----------|-------|
| Chrome/Edge 100+ | Yes | Full support |
| Firefox 100+ | Yes | Full support |
| Safari 16.4+ | Yes | Full support |
| Opera 90+ | Yes | Full support |
| Brave | Yes | Full support |
| IE11 | No | Not supported |
| Android WebView | Partial | Extension unavailable; web scanner works |

## Known limitations

- Chrome Manifest V3 extension: service worker background, no persistent background page
- Firefox extension: same MV3 manifest, works in Firefox 109+
- Safari extension: requires native wrapper (iOS/macOS); web version works
- `prefers-reduced-motion`: respected globally; all animations disabled
- Canvas monitoring chart: requires canvas 2D context (all modern browsers)
- `fetch` with `keepalive`: used for analytics; may be dropped when tab closes (acceptable loss)

## Mobile

- Responsive layout tested at 320px–1440px
- Touch targets ≥44px on all interactive elements
- Extension popup: 320px wide, 480px tall

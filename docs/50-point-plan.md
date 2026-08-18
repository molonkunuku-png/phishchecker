# PhishChecker 50-Point Improvement Plan

## Completed
1. Theme toggle rename + aria-label
2. Version moved to footer
3. Improved input/select contrast in dark mode
4. Mobile hamburger nav
5. Scan form stacks on mobile
6. Empty state prompt below scan form
7. Animated SVG risk score gauge
8. Loading spinner inside Scan button
9. History empty state + overflow guard
10. Footer legal links + copyright
11. Skip-to-content link
12. Active nav state
13. Focus-visible styles + WCAG contrast pass
14. Findings severity badges + explanations
15. Relative timestamps
16. SSL grade/cert details in results
17. Print + Export report
18. Light/dark toggle icons
19. Privacy badge near form
20. Privacy/Terms static pages
21. Quick mode: lightweight scan
22. Standard mode: balanced scan
23. IT mode: deep technical scan
24. Mode help text under selector
25. Error state with retry
26. Domain age + duration fields
27. Certificate grade/details
28. Relative timestamps
29. Active nav state styling
30. Focus-visible styles
31. Hover states for interactive elements
32. Dark mode toggle icons
33. Print CSS hardening
34. Findings severity badges
35. Findings expand/collapse explanations
36. Skeleton loaders
37. History empty state + overflow guard
38. Loading spinner in Scan button
39. Print button in results
40. Export report button
41. Skip-to-content link
42. Mobile hamburger nav
43. Scan form mobile stack
44. How it works mobile stack
45. Touch target size audit
46. Mobile contrast pass
47. Debounced URL validation
48. Auto-focus input on load
49. Nav scroll shadow
50. Keyboard shortcut hint
51. Score/risk alignment
52. SSL validation escalates risk
53. Mode label casing fix everywhere
54. Score breakdown panel
55. Redirect chain visualization
56. Findings filter chips + expand/collapse all
57. URL validation helper
58. Certificate copy button
59. Changelog footer
60. Live threat-intel blocklist lookup

## Completed backend foundation
1. Request ID + structured logging middleware
2. Rate-limit response headers (`Retry-After`, `X-RateLimit-*`)
3. Request validation helpers for scan/bulk payloads
4. Feed health metadata endpoint (`/api/v2/status/feeds`)
5. Metrics endpoint (`/metrics`)
6. Startup config validation guard
7. Graceful shutdown hook via `SIGTERM`/`SIGINT`
8. IP allowlist/blocklist middleware file (`middleware/ip_control.py`)
9. OpenAPI spec added at `docs/openapi.json`
10. Export CSV expanded to include finished_at + duration_ms


## Completed (from prior work)
1. Theme toggle rename + aria-label
2. Version moved to footer
3. Improved input/select contrast in dark mode
4. Mobile hamburger nav
5. Scan form stacks on mobile
6. Empty state prompt below scan form
7. Animated SVG risk score gauge
8. Loading spinner inside Scan button
9. History empty state + overflow guard
10. Footer legal links + copyright
11. Skip-to-content link
12. Active nav state
13. Focus-visible states + WCAG contrast pass
14. Findings severity badges + explanations
15. Relative timestamps
16. SSL grade/cert details in results
17. Print + Export report
18. Light/dark toggle icons
19. Privacy badge near form
20. Privacy/Terms static pages
21. Quick mode: lightweight scan
22. Standard mode: balanced scan
23. IT mode: deep technical scan
24. Mode help text under selector
25. Error state with retry
26. Domain age + duration fields
27. Certificate grade/details
28. Relative timestamps
29. Active nav state styling
30. Focus-visible styles
31. Hover states for interactive elements
32. Dark mode toggle icons
33. Print CSS hardening
34. Findings severity badges
35. Findings expand/collapse explanations
36. Skeleton loaders
37. History empty state + overflow guard
38. Loading spinner in Scan button
39. Print button in results
40. Export report button
41. Skip-to-content link
42. Mobile hamburger nav
43. Scan form mobile stack
44. How it works mobile stack
45. Touch target size audit
46. Mobile contrast pass
47. Debounced URL validation
48. Auto-focus input on load
49. Nav scroll shadow
50. Keyboard shortcut hint

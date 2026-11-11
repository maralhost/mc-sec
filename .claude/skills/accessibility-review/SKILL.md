---
name: accessibility-review
description: Run a WCAG 2.1 AA accessibility audit on a design or page. Trigger with "audit accessibility", "check a11y", "is this accessible?", or when reviewing a design for color contrast, keyboard navigation, touch target size, or screen reader behavior before handoff. In MC-Team, audit the preview pages; RTL and Persian checks live in mcteam-rtl-review (دسترس‌پذیری).
argument-hint: "<Figma URL, URL, or description>"
---

<!-- Vendored from anthropics/knowledge-work-plugins `design/skills/accessibility-review/SKILL.md` at commit e050c2e (2026-11-06), Apache-2.0 (../LICENSE-knowledge-work-plugins). Changed for MC-Team: appended an MC-Team note to the description; added the «در MC-Team» section at the end; removed the CONNECTORS.md pointer and the "If Connectors Available" section (no connectors here). Do not fetch it from the network; update by copying a pinned commit. -->

# /accessibility-review

Audit a design or page for WCAG 2.1 AA accessibility compliance.

## Usage

```
/accessibility-review $ARGUMENTS
```

Audit for accessibility: @$1

## WCAG 2.1 AA Quick Reference

### Perceivable
- **1.1.1** Non-text content has alt text
- **1.3.1** Info and structure conveyed semantically
- **1.4.3** Contrast ratio >= 4.5:1 (normal text), >= 3:1 (large text)
- **1.4.11** Non-text contrast >= 3:1 (UI components, graphics)

### Operable
- **2.1.1** All functionality available via keyboard
- **2.4.3** Logical focus order
- **2.4.7** Visible focus indicator
- **2.5.5** Touch target >= 44x44 CSS pixels

### Understandable
- **3.2.1** Predictable on focus (no unexpected changes)
- **3.3.1** Error identification (describe the error)
- **3.3.2** Labels or instructions for inputs

### Robust
- **4.1.2** Name, role, value for all UI components

## Common Issues

1. Insufficient color contrast
2. Missing form labels
3. No keyboard access to interactive elements
4. Missing alt text on meaningful images
5. Focus traps in modals
6. Missing ARIA landmarks
7. Auto-playing media without controls
8. Time limits without extension options

## Testing Approach

1. Automated scan (catches ~30% of issues)
2. Keyboard-only navigation
3. Screen reader testing (VoiceOver, NVDA)
4. Color contrast verification
5. Zoom to 200% — does layout break?

## Output

```markdown
## Accessibility Audit: [Design/Page Name]
**Standard:** WCAG 2.1 AA | **Date:** [Date]

### Summary
**Issues found:** [X] | **Critical:** [X] | **Major:** [X] | **Minor:** [X]

### Findings

#### Perceivable
| # | Issue | WCAG Criterion | Severity | Recommendation |
|---|-------|---------------|----------|----------------|
| 1 | [Issue] | [1.4.3 Contrast] | 🔴 Critical | [Fix] |

#### Operable
| # | Issue | WCAG Criterion | Severity | Recommendation |
|---|-------|---------------|----------|----------------|
| 1 | [Issue] | [2.1.1 Keyboard] | 🟡 Major | [Fix] |

#### Understandable
| # | Issue | WCAG Criterion | Severity | Recommendation |
|---|-------|---------------|----------|----------------|
| 1 | [Issue] | [3.3.2 Labels] | 🟢 Minor | [Fix] |

#### Robust
| # | Issue | WCAG Criterion | Severity | Recommendation |
|---|-------|---------------|----------|----------------|
| 1 | [Issue] | [4.1.2 Name, Role, Value] | 🟡 Major | [Fix] |

### Color Contrast Check
| Element | Foreground | Background | Ratio | Required | Pass? |
|---------|-----------|------------|-------|----------|-------|
| [Body text] | [color] | [color] | [X]:1 | 4.5:1 | ✅/❌ |

### Keyboard Navigation
| Element | Tab Order | Enter/Space | Escape | Arrow Keys |
|---------|-----------|-------------|--------|------------|
| [Element] | [Order] | [Behavior] | [Behavior] | [Behavior] |

### Screen Reader
| Element | Announced As | Issue |
|---------|-------------|-------|
| [Element] | [What SR says] | [Problem if any] |

### Priority Fixes
1. **[Critical fix]** — Affects [who] and blocks [what]
2. **[Major fix]** — Improves [what] for [who]
3. **[Minor fix]** — Nice to have
```

## Tips

1. **Start with contrast and keyboard** — These catch the most common and impactful issues.
2. **Test with real assistive technology** — My audit is a great start, but manual testing with VoiceOver/NVDA catches things I can't.
3. **Prioritize by impact** — Fix issues that block users first, polish later.

## در MC-Team
- صفحه‌ها را در پیش‌نمایش بسنج (`tests/tools/preview.php`؛ شخص‌ها با `&as=`، حالت تیره با `&dark=1`، گوشی ۳۹۰ پیکسل). بی صفحه‌خوان واقعی، بخش «Screen Reader» را از درخت دسترس‌پذیری مرورگر (`read_page`) بنویس و بگو با صفحه‌خوان آزموده نشد.
- جهت، bidi، رقم فارسی، فونت Ray و کنتراست حالت تیره‌ی Lagom2 در `mcteam-rtl-review` است. اول آن را اجرا کن و این‌جا تکرارش نکن.
- **سنجه‌های ویژه‌ی این ماژول:**
  - چیپ‌های وضعیت (روشن و خاموش، سرپرست تیم) متن دارند، نه فقط رنگ.
  - منوی گوشی و دکمه‌ی تمام‌صفحه وضعیتشان را اعلام می‌کنند (`aria-expanded` و `aria-pressed`).
  - پس از جابه‌جایی بی بارگذاری (pjax) فوکوس به پیام نتیجه یا محتوای تازه می‌رود (`client.js`) و Escape منوها را می‌بندد.
  - چک‌باکس هر سرویس تیم برچسب کامل دارد (نام سرویس و دامنه).
- **هدف لمسی:** دکمه‌های اصلی ۴۴ پیکسل؛ پیوندهای ردیف جدول (دادن سهم، برگرداندن) دست‌کم ۲۴ پیکسل و با فاصله از هم.
- خروجی فارسی است، با همان سه سطح شدت و `file:line`.

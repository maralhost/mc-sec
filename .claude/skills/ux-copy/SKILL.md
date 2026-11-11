---
name: ux-copy
description: Write or review UX copy — microcopy, error messages, empty states, CTAs. Trigger with "write copy for", "what should this button say?", "review this error message", or when naming a CTA, wording a confirmation dialog, filling an empty state, or writing onboarding text. In MC-Team all copy is Persian; use the glossary in the MC-Team section (متن دکمه، پیام خطا، متن رابط).
argument-hint: "<context or copy to review>"
---

<!-- Vendored from anthropics/knowledge-work-plugins `design/skills/ux-copy/SKILL.md` at commit e050c2e (2026-11-06), Apache-2.0 (../LICENSE-knowledge-work-plugins). Changed for MC-Team: appended an MC-Team note to the description; added the «در MC-Team» section at the end; removed the CONNECTORS.md pointer and the "If Connectors Available" section (no connectors here). Do not fetch it from the network; update by copying a pinned commit. -->

# /ux-copy

Write or review UX copy for any interface context.

## Usage

```
/ux-copy $ARGUMENTS
```

## What I Need From You

- **Context**: What screen, flow, or feature?
- **User state**: What is the user trying to do? How are they feeling?
- **Tone**: Formal, friendly, playful, reassuring?
- **Constraints**: Character limits, platform guidelines?

## Principles

1. **Clear**: Say exactly what you mean. No jargon, no ambiguity.
2. **Concise**: Use the fewest words that convey the full meaning.
3. **Consistent**: Same terms for the same things everywhere.
4. **Useful**: Every word should help the user accomplish their goal.
5. **Human**: Write like a helpful person, not a robot.

## Copy Patterns

### CTAs
- Start with a verb: "Start free trial", "Save changes", "Download report"
- Be specific: "Create account" not "Submit"
- Match the outcome to the label

### Error Messages
Structure: What happened + Why + How to fix
- "Payment declined. Your card was declined by your bank. Try a different card or contact your bank."

### Empty States
Structure: What this is + Why it's empty + How to start
- "No projects yet. Create your first project to start collaborating with your team."

### Confirmation Dialogs
- Make the action clear: "Delete 3 files?" not "Are you sure?"
- Describe consequences: "This can't be undone"
- Label buttons with the action: "Delete files" / "Keep files" not "OK" / "Cancel"

### Tooltips
- Concise, helpful, never obvious

### Loading States
- Set expectations, reduce anxiety

### Onboarding
- Progressive disclosure, one concept at a time

## Voice and Tone

Adapt tone to context:
- **Success**: Celebratory but not over the top
- **Error**: Empathetic and helpful
- **Warning**: Clear and actionable
- **Neutral**: Informative and concise

## Output

```markdown
## UX Copy: [Context]

### Recommended Copy
**[Element]**: [Copy]

### Alternatives
| Option | Copy | Tone | Best For |
|--------|------|------|----------|
| A | [Copy] | [Tone] | [When to use] |
| B | [Copy] | [Tone] | [When to use] |
| C | [Copy] | [Tone] | [When to use] |

### Rationale
[Why this copy works — user context, clarity, action-orientation]

### Localization Notes
[Anything translators should know — idioms to avoid, character expansion, cultural context]
```

## Tips

1. **Be specific about context** — "Error message when payment fails" is better than "error message."
2. **Share your brand voice** — "We're professional but warm" helps me match your tone.
3. **Consider the user's emotional state** — Error messages need empathy. Success messages can celebrate.

## در MC-Team
همه‌ی متن رابط فارسی است (قانون پروژه؛ `tests/persian_test.php` متن انگلیسی را می‌گیرد).
- **الگوها به فارسی:** دکمه با فعل و مشخص («ذخیره‌ی سرویس‌های تیم»، «فرستادن دعوت»)، نه «ثبت» یا «تأیید». خطا: چه شد + چرا + قدم بعدی. حالت خالی: این چیست + چرا خالی است + اولین کار. تأیید فقط برای کار برگشت‌ناپذیر، با نام کار روی دکمه («بایگانی تیم» و «نگه داشتن»).
- **واژه‌نامه** (یک واژه برای یک چیز؛ متنی که واژه‌ی دیگری به کار برده یافته است):
  - **سازمان:** همه‌ی حساب‌های یک شرکت مشتری با هم.
  - **حساب:** یک حساب مشتری WHMCS (client). در کد `workspace` است و متن‌های قدیمی‌تر «فضا» می‌گویند. ⚠ هر دو واژه هنوز در رابط دیده می‌شوند؛ یکی کردنشان تصمیم بنیان‌گذار است.
  - **حساب اصلی** و **حساب مجزا:** حساب اول سازمان، و حسابی که فقط برای فاکتور رسمی به نام دیگر ساخته شده است.
  - **تیم:** گروهی از افراد داخل یک حساب، با سرویس‌های خودش.
  - **سهم تیم:** بخشی از اعتبار حساب که مالک یا مالی به تیم داده است. **اعتبار آزاد:** بخشی که به هیچ تیمی داده نشده است.
  - **نقش‌ها:** مالک حساب، مدیر، فنی، مالی، پشتیبانی، فقط دیدن، سرپرست تیم، عضو تیم.
  - **صورت‌وضعیت** (نه «سند مالیاتی»)، **درخواست به پشتیبانی**، **رویداد**، **خبر**.
  - «مارال کلاد»، «ریال»، رقم فارسی، تاریخ شمسی، نیم‌فاصله و گیومه‌ی «».
- **لحن:** محترمانه و ساده، بی «لطفاً» در هر جمله و بی عذرخواهی در خطا. نام منوهای انگلیسی WHMCS (`Switch Account`) داخل `<bdi>` می‌آید.
- «Localization Notes» در قالب خروجی این‌جا یعنی طول متن روی گوشی ۳۹۰ پیکسل، و این‌که جمله با عدد یا واژه‌ی لاتین شروع نشود (جهت پاراگراف عوض می‌شود).
- متن پیشنهادی را کنار فایل و خط فعلی‌اش بنویس (`lib/Client/*.php`، `lib/Admin/*.php`).

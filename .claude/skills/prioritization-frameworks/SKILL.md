---
name: prioritization-frameworks
description: "Reference guide to 9 prioritization frameworks with formulas, when-to-use guidance, and templates — RICE, ICE, Kano, MoSCoW, Opportunity Score, and more. Use when selecting a prioritization method, comparing frameworks like RICE vs ICE, or learning how different prioritization approaches work."
---

<!-- Adapted from phuryn/pm-skills (MIT, LICENSE-pm-skills), commit 9af7bfd. Removed: the Further Reading and template links
     (course and Google Drive pages); $ARGUMENTS replaced with the MC-Care section or idea at hand. -->

> **یادداشت MC-Care:** کاربران ماژول کارشناس‌ها، سرپرست‌ها و مدیران تیم مارال کلاد‌اند و رابط فارسی و راست‌به‌چپ است. پیش از این اسکیل `mc-product-designer` را بخوانید؛ قاعده‌های آن و قاعده‌های ثابت `CLAUDE.md` مقدم‌اند. راست‌به‌چپ و دسترس‌پذیری با `mc-care-rtl-review` بررسی می‌شود. خروجی بزرگ در `docs/` ذخیره شود (مثل `docs/product-ideas.md`). «مشتری» در این متن‌ها یعنی کاربر ماژول (تیم مارال)، یا مشتری مارال وقتی کار به پنل مشتری می‌رسد.


## Prioritization Frameworks Reference

A reference guide to help you select and apply the right prioritization framework for your context.

### Core Principle

Never allow customers to design solutions. Prioritize **problems (opportunities)**, not features.

When a group scores or ranks items together, collect the votes independently before the discussion, so the most senior opinion doesn't anchor everyone else.

### Opportunity Score (Dan Olsen, *The Lean Product Playbook*)

The recommended framework for prioritizing customer problems.

Survey customers on **Importance** and **Satisfaction** for each need (normalize to 0–1 scale).

Three related formulas:
- **Current value** = Importance × Satisfaction
- **Opportunity Score** = Importance × (1 − Satisfaction)
- **Customer value created** = Importance × (S2 − S1), where S1 = satisfaction before, S2 = satisfaction after

High Importance + low Satisfaction = highest Opportunity Score = best opportunities. Plot on an Importance vs Satisfaction chart — upper-left quadrant is the sweet spot. Prioritizes customer problems, not solutions.

### ICE Framework

Useful for prioritizing initiatives and ideas. Considers not only value but also risk and economic factors.

- **I** (Impact) = Opportunity Score × Number of Customers affected
- **C** (Confidence) = How confident are we? (1-10). Accounts for risk.
- **E** (Ease) = How easy is it to implement? (1-10). Accounts for economic factors.

**Score** = I × C × E. Higher = prioritize first.

### RICE Framework

Splits ICE's Impact into two separate factors. Useful for larger teams that need more granularity.

- **R** (Reach) = Number of customers affected
- **I** (Impact) = Opportunity Score (value per customer)
- **C** (Confidence) = How confident are we? (0-100%)
- **E** (Effort) = How much effort to implement? (person-months)

**Score** = (R × I × C) / E

### 9 Frameworks Overview

| Framework | Best For | Key Insight |
|-----------|----------|-------------|
| Eisenhower Matrix | Personal tasks | Urgent vs Important — for individual PM task management |
| Impact vs Effort | Tasks/initiatives | Simple 2×2 — quick triage, not rigorous for strategic decisions |
| Risk vs Reward | Initiatives | Like Impact vs Effort but accounts for uncertainty |
| **Opportunity Score** | Customer problems | **Recommended.** Importance × (1 − Satisfaction). Normalize to 0–1. |
| Kano Model | Understanding expectations | Must-be, Performance, Attractive, Indifferent, Reverse. For understanding, not prioritizing. |
| Weighted Decision Matrix | Multi-factor decisions | Assign weights to criteria, score each option. Useful for stakeholder buy-in. |
| **ICE** | Ideas/initiatives | Impact × Confidence × Ease. Recommended for quick prioritization. |
| **RICE** | Ideas at scale | (Reach × Impact × Confidence) / Effort. Adds Reach to ICE. |
| MoSCoW | Requirements | Must/Should/Could/Won't. Caution: project management origin. |

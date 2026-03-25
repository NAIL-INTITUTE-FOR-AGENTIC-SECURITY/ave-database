# 📊 Financial Reporting Schedule

## Reporting Cadence

| Report | Frequency | Due Date | Audience | Owner |
|--------|-----------|----------|----------|-------|
| Monthly Dashboard | Monthly | 5th of following month | Executive Director | Finance |
| Quarterly Review | Quarterly | 15th of following month | Board of Directors | Finance + ED |
| Annual Report | Annual | Within 90 days of FY end | Public (published) | Board + ED |
| Grant Reports | Per grant terms | Varies | Funders | Research Lead + Finance |
| Tax Filing | Annual | Per jurisdiction deadline | Authorities | External Accountant |

---

## Monthly Dashboard

Quick financial health check (1-page summary).

### Contents
- Revenue vs forecast (by stream)
- Expenses vs budget (by category)
- Cash position
- Accounts receivable aging
- Key metrics: API customers, certifications issued, partner count
- Red/amber/green status indicators

### Distribution
- Email to Executive Director
- Stored in `sustainability/reports/monthly/YYYY-MM.md`

---

## Quarterly Board Report

Detailed financial review for Board of Directors.

### Contents
1. **Executive Summary** — 1 paragraph on financial health
2. **Revenue Performance** — By stream, vs forecast, trend charts
3. **Expense Review** — By category, vs budget, notable variances
4. **Cash Flow Statement** — Inflows, outflows, ending balance
5. **Reserve Fund Status** — Current balance, months of runway
6. **KPI Dashboard** — Growth metrics, customer metrics, community metrics
7. **Risk Register Update** — New risks, changed assessments
8. **Forecast Update** — Revised projections if >10% variance
9. **Board Actions Required** — Decisions needed

### Process
1. Finance prepares draft by day 10
2. Executive Director reviews by day 12
3. Board receives by day 15
4. Board meeting to discuss within 30 days

### Distribution
- Board portal (secure)
- Stored in `sustainability/reports/quarterly/YYYY-QN.md`

---

## Annual Report

Public-facing accountability document.

### Contents
1. **Letter from the Director**
2. **Year in Review** — Key accomplishments
3. **Impact Metrics** — AVE entries, users, certifications, partnerships
4. **Financial Statements**
   - Statement of Activities (P&L)
   - Statement of Financial Position (Balance Sheet)
   - Statement of Cash Flows
   - Notes to Financial Statements
5. **Revenue Breakdown** — By stream with year-over-year comparison
6. **Expense Breakdown** — By category with year-over-year comparison
7. **Community Report** — Contributors, GitHub activity, events
8. **Research Output** — Papers, experiments, new AVE entries
9. **Governance Report** — Board activities, policy changes
10. **Looking Ahead** — Next year priorities and budget overview

### Process
1. FY closes
2. External accountant reviews (within 30 days)
3. Board audit committee reviews (within 60 days)
4. Board approves (within 75 days)
5. Published on website (within 90 days)

### Distribution
- Website: nailinstitute.org/reports
- GitHub: `sustainability/reports/annual/YYYY.md`
- Email to all partners and major donors

---

## Grant Reporting

Each grant has its own reporting requirements defined in the
grant agreement. General guidelines:

| Requirement | Standard |
|-------------|----------|
| Financial reports | Per grant schedule (typically quarterly or semi-annual) |
| Narrative reports | Per grant schedule |
| Final report | Within 90 days of grant end |
| Audit | If required by funder |
| Record retention | 7 years from grant end |

### Process
1. Research Lead drafts narrative sections
2. Finance prepares financial sections
3. Executive Director reviews and approves
4. Submitted via funder's portal/process
5. Copy stored in `sustainability/grants/reports/`

---

## Audit

### External Audit
- **When**: Annually, once revenue exceeds $1M/year
- **Scope**: Full financial statements
- **Standard**: UK GAAP or IFRS (as appropriate)
- **Firm**: Independent, rotated every 5 years
- **Output**: Published with annual report

### Internal Controls
- Dual approval for expenses > $5,000
- Board approval for expenses > $25,000
- Monthly bank reconciliation
- Quarterly budget variance review
- Annual policy review

---

## File Structure

```
sustainability/reports/
├── monthly/
│   ├── 2025-07.md
│   ├── 2025-08.md
│   └── ...
├── quarterly/
│   ├── 2025-Q3.md
│   ├── 2025-Q4.md
│   └── ...
├── annual/
│   ├── 2025.md
│   └── ...
└── grant/
    ├── [grant-name]-Q1.md
    └── ...
```

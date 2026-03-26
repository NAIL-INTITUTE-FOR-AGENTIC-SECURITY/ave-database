# Chapter Handbook — Operations Manual for Chapter Leads

A practical, step-by-step guide for running a NAIL Institute Regional Chapter.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Communication Channels](#2-communication-channels)
3. [Running Events](#3-running-events)
4. [Growing Membership](#4-growing-membership)
5. [AVE Contributions](#5-ave-contributions)
6. [Reporting & Metrics](#6-reporting--metrics)
7. [Budget Management](#7-budget-management)
8. [Partnerships](#8-partnerships)
9. [Succession Planning](#9-succession-planning)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Getting Started

### First 30 Days

- [ ] Complete onboarding call with Global Chapters Committee (GCC)
- [ ] Set up regional Slack channel (`#chapter-<region>`)
- [ ] Create regional mailing list via chapters@nailinstitute.org
- [ ] Request brand assets (logo, slide deck, templates)
- [ ] Draft your Chapter Charter using the [template](../templates/chapter_charter.md)
- [ ] Introduce yourself on `#regional-chapters` Slack
- [ ] Schedule your first community meetup

### First 90 Days (Probation Period)

- [ ] Host at least 1 event
- [ ] Recruit 5+ chapter members
- [ ] Submit your first quarterly report
- [ ] Attend 3 monthly GCC sync calls
- [ ] Identify your Co-Lead
- [ ] Set up recurring event schedule

### First Year Goals

- [ ] Host 6+ events
- [ ] Submit 2+ AVE cards from regional research
- [ ] Establish 2+ local partnerships
- [ ] Train your Co-Lead as succession backup
- [ ] Present at 1 GCC cross-chapter session

## 2. Communication Channels

### Required Channels
| Channel | Platform | Purpose |
|---------|----------|---------|
| `#chapter-<region>` | Slack | General chapter discussion |
| `#chapter-<region>-leads` | Slack | Chapter leadership only |
| Mailing list | Email | Announcements, event invites |
| GitHub Discussions | GitHub | Technical discussions, RFCs |

### Best Practices
- Post at least 2× per week in your Slack channel
- Send a monthly newsletter via mailing list
- Respond to questions within 24 hours
- Pin important resources and upcoming events
- Keep `#chapter-<region>-leads` for decision-making only

## 3. Running Events

### Event Planning Checklist (4 weeks out)

**Week 4**: Decide topic, confirm speaker(s), choose date/venue
**Week 3**: Create event page, open registration, draft announcement
**Week 2**: Promote on all channels, send personal invitations
**Week 1**: Send reminder, confirm logistics, prepare materials
**Day of**: Run event, take photos, collect feedback
**Week after**: Share recording + slides, publish summary, thank speakers

### Event Formats
See the [Event Toolkit](../templates/event_toolkit.md) for detailed templates.

### Virtual Events
- Use Zoom, Google Meet, or Discord (free tier sufficient)
- Record with speaker consent
- Use breakout rooms for networking portions
- Have a moderator for chat / Q&A

### In-Person Events
- Seek university or corporate venue sponsors
- Budget $10-20/person for catering
- Arrange A/V equipment for recording
- Have name tags and a sign-in sheet
- Follow local health/safety regulations

## 4. Growing Membership

### Recruitment Strategies
1. **Local AI/ML meetups**: Present at existing events, invite attendees
2. **University outreach**: Contact CS/AI department heads
3. **Conference presence**: Set up a NAIL booth or distribute flyers
4. **Online content**: Write blog posts, record short videos
5. **Referral programme**: Ask members to invite 1 colleague each
6. **Social media**: Tag @NAILInstitute, use regional hashtags

### Retention Strategies
1. **Consistent events**: Maintain a predictable schedule
2. **Value delivery**: Ensure every event teaches something actionable
3. **Recognition**: Acknowledge contributors publicly
4. **Mentorship**: Pair newcomers with experienced members
5. **Pathways**: Offer roles (speaker, organiser, reviewer, ambassador)

### Diversity & Inclusion
- Ensure speaker diversity (experience level, background, affiliation)
- Offer events at varied times (accommodate different schedules)
- Provide virtual options for all in-person events
- Use inclusive language in all communications
- Actively recruit from underrepresented groups

## 5. AVE Contributions

### Encouraging Contributions
- Run "AVE Card Writing" workshops (use training/ materials)
- Assign pairs to co-author cards
- Host monthly "threat spotting" sessions
- Review new research papers for potential AVE candidates
- Recognise contributors on the NAIL Hall of Fame

### Contribution Process
1. Member identifies a potential agentic AI vulnerability
2. Draft AVE card using the schema (v1 or v2)
3. Chapter peer review (at least 1 other member)
4. Submit PR to `ave-database` repository
5. NAIL review committee evaluates
6. If accepted: card published, contributor credited

### Quality Standards
- All cards must pass `schema-v2/tools/validate_card.py`
- Evidence must be verifiable (link to paper, PoC, or incident report)
- AVSS scores must be justified in the submission PR description

## 6. Reporting & Metrics

### Quarterly Report Template

```markdown
# NAIL [Region] Chapter — Q[N] [YYYY] Report

## Membership
- Active members: [N] (Δ from last quarter: +/- N)
- New members: [N]
- Inactive members: [N]

## Events
| Date | Event | Attendees | Format |
|------|-------|-----------|--------|
| | | | |

## AVE Contributions
- Cards submitted: [N]
- Cards accepted: [N]
- Cards in review: [N]

## Partnerships
- New partnerships: [list]
- Active partnerships: [list]

## Highlights
- [Notable achievements]

## Challenges
- [Issues and blockers]

## Plans for Next Quarter
- [Upcoming events]
- [Goals]

## Budget
- Allocated: $[N]
- Spent: $[N]
- Remaining: $[N]
- Major expenses: [list]
```

### Key Metrics to Track
| Metric | Target | How to Measure |
|--------|--------|----------------|
| Active members | Growing | Slack + event attendance |
| Events per quarter | 2+ | Event calendar |
| Average attendance | 15+ | Registration / headcount |
| AVE submissions | 1+/quarter | GitHub PRs |
| NPS (member satisfaction) | 8+ | Quarterly survey |

## 7. Budget Management

### Annual Budget (Typical)
| Category | Allocation |
|----------|-----------|
| Events (venue, catering) | 40% |
| Speaker support (travel) | 25% |
| Marketing & swag | 15% |
| Tools & platforms | 10% |
| Contingency | 10% |

### Approval Thresholds
- **< $500**: Chapter Lead approves
- **$500-$2,000**: GCC approval required (submit request form)
- **> $2,000**: GCC + Board approval

### Reimbursement Process
1. Submit receipts to chapters-finance@nailinstitute.org
2. Include: event name, date, amount, category
3. Reimbursement within 30 days

## 8. Partnerships

### Types of Partners
- **University partners**: Host events, joint research, student pipeline
- **Corporate sponsors**: Venue, funding, speaker access
- **Government/policy**: Regulatory engagement, public consultations
- **Other communities**: Cross-promotion, joint events

### Partnership Process
1. Identify potential partner aligned with NAIL mission
2. Initial outreach (use email templates in brand guidelines)
3. Discuss mutual benefits and scope
4. Draft informal MOU (template available from GCC)
5. GCC approval for formal partnerships
6. Announce on chapter channels

## 9. Succession Planning

### Why It Matters
- Chapters should survive any single person leaving
- Leadership transitions should be smooth and planned

### Steps
1. Identify your Co-Lead within 6 months of starting
2. Document all processes (this handbook helps!)
3. Share access to all accounts and tools
4. Have Co-Lead run at least 2 events independently
5. Begin transition 3 months before your term ends
6. Complete the handover checklist:

### Handover Checklist
- [ ] All account credentials transferred
- [ ] Mailing list admin access transferred
- [ ] Slack channel ownership transferred
- [ ] Budget status and outstanding expenses documented
- [ ] Active partnerships and contact details shared
- [ ] Upcoming events calendar handed over
- [ ] GCC introduced to new lead

## 10. Troubleshooting

### Low Attendance?
- Survey members about preferred topics and times
- Try different event formats (workshop vs. talk vs. social)
- Partner with a popular local meetup for a joint event
- Post-event content (recording, blog) to demonstrate value

### No AVE Contributions?
- Run a dedicated "write your first AVE card" workshop
- Start with a group exercise: pick a published paper and draft a card together
- Lower the barrier: accept draft-quality submissions for collaborative refinement

### Internal Conflict?
- Address directly with the parties involved
- Refer to Code of Conduct
- Escalate to GCC if not resolved within 14 days

### Budget Shortfall?
- Seek local corporate sponsors
- Use free venues (university lecture halls, co-working spaces)
- Run more virtual events (zero venue cost)
- Apply for GCC supplementary funding

---

*Questions? Reach out on `#regional-chapters` or email chapters@nailinstitute.org.*

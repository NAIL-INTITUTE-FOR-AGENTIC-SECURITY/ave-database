# Appendix B: Contributor Credits

> Acknowledging the researchers, practitioners, and organisations
> that made the inaugural AVE Report possible.

---

## Report Team

### Report Lead
- **TBD** — NAIL Institute

### Chapter Authors

| Chapter | Lead Author | Reviewers |
|---------|------------|-----------|
| 1. Executive Summary | NAIL Institute | Full review board |
| 2. Year in Review | NAIL Institute | Full review board |
| 3. Vulnerability Landscape | NAIL Research Team | Statistics reviewer |
| 4. Category Deep-Dives | NAIL Research Team | Category experts |
| 5. Severity & Scoring | AVSS Working Group | Statistics reviewer |
| 6. Multi-Agent Threats | NAIL Research Team | Multi-agent experts |
| 7. Defence Effectiveness | NAIL Defence Team | Red-team reviewers |
| 8. Industry Impact | NAIL Industry Relations | Sector reviewers |
| 9. Regulatory Landscape | NAIL Policy Team | Legal reviewer |
| 10. Research Highlights | NAIL Research Team | Academic reviewers |
| 11. Predictions & Outlook | NAIL Institute | Expert panel |
| 12. Methodology | NAIL Research Team | Statistics reviewer |

### Data Analysis
- **NAIL Data Engineering Team** — Statistical analysis pipeline
- **Script development**: `annual-report/2025/scripts/generate_report_data.py`

### Design and Production
- **NAIL Communications Team** — Report design, PDF generation, web version

---

## AVE Database Contributors

### Core Research Team (NAIL Institute)

The NAIL Institute research team conducted the foundational experiments
and created the initial AVE card set:

| Experiment | Focus Area |
|-----------|-----------|
| Experiments 1–12 | Foundational vulnerability characterisation |
| Experiments 13–24 | Defence mechanism evaluation |
| Experiment 25 | Multi-agent collusion |
| Experiment 26 | Confused deputy exploitation |
| Experiment 27 | Shadow delegation |
| Experiments 28–34 | Cross-agent propagation and consensus |
| Experiments 35–40+ | Advanced adversarial techniques |

### Community Contributors

We gratefully acknowledge the researchers who submitted AVE cards through
the community contribution process:

| Contributor Handle | Cards Submitted | Affiliation |
|-------------------|-----------------|-------------|
| [To be populated from contributor database] | | |

*Note: Contributors are listed by their chosen handle. Some contributors
have opted for anonymous attribution.*

### Responsible Disclosure

The following individuals reported vulnerabilities through the NAIL
responsible disclosure process:

| Reporter | AVE Cards | Status |
|----------|-----------|--------|
| [To be populated] | | Published |

---

## Practitioner Survey Contributors

### Survey Design
- NAIL Research Team
- External survey methodology reviewer

### Respondents
- **87** security and AI professionals from **14** countries
- We thank all respondents for their time and insights
- Individual responses are anonymised per our privacy policy

---

## Expert Panel

The following experts participated in semi-structured interviews that
informed Chapters 6, 7, 8, and 11:

| Expert | Affiliation | Domain |
|--------|------------|--------|
| [To be populated after consent verification] | | |

*Note: Expert participation does not imply endorsement of report findings.
All experts have reviewed and approved the use of their insights.*

---

## Academic Reviewers

The following academic researchers reviewed chapter drafts for technical
accuracy:

| Reviewer | Institution | Chapters Reviewed |
|----------|-----------|------------------|
| [To be populated] | | |

---

## Organisational Partners

We acknowledge the following organisations for their support of the
AVE database and annual report process:

### Research Partners
- Organisations that contributed anonymised incident data
- Institutions hosting NAIL Academic Programme pilots
- Conference organisers who provided platforms for presentation

### Vendor Integration Partners

| Partner | Integration Type |
|---------|-----------------|
| Splunk | SIEM (reference integration) |
| Microsoft | Sentinel SIEM integration |
| ServiceNow | GRC / ITSM integration |
| CrowdStrike | EDR integration |
| Elastic | SIEM integration |
| Palo Alto Networks | XSOAR SOAR integration |
| Tenable | Vulnerability management integration |
| Atlassian | Jira issue tracking integration |
| Snyk | Developer security integration |

### Open-Source Community

The NAIL AVE Database is built on open-source principles. We thank the
broader open-source security community for:
- GitHub issue reports and pull requests
- Bug reports and feature requests
- Documentation improvements
- Translation assistance

---

## How to Contribute

### To the AVE Database
1. **Submit a card**: Use `python -m ave submit --interactive`
2. **Report a vulnerability**: nail-responsible-disclosure@nailinstitute.org
3. **Contribute code**: See `CONTRIBUTING.md` in the repository
4. **Review cards**: Join the reviewer pool via community@nailinstitute.org

### To the Annual Report
1. **Participate in the survey**: Distributed each December
2. **Share incident data**: Anonymised case studies welcome
3. **Review chapters**: Reviewers needed for each edition
4. **Provide expert insights**: Expert panel interviews conducted annually

### To the Academic Programme
1. **Adopt modules**: See `academic/courses/README.md` for adoption guide
2. **Contribute exercises**: Additional lab exercises welcome
3. **Translate materials**: Help make the curriculum accessible globally
4. **Provide feedback**: Report issues or suggestions via GitHub

---

## Licensing

| Component | Licence |
|-----------|---------|
| AVE Database | CC BY 4.0 |
| Annual Report | CC BY 4.0 |
| AVE Python SDK | Apache 2.0 |
| Academic Course Materials | CC BY 4.0 |
| Analysis Scripts | Apache 2.0 |

---

## Citation

To cite this report:

```bibtex
@report{nail_ave_annual_2025,
  title   = {State of Agentic AI Security: Annual AVE Report 2025},
  author  = {{NAIL Institute for Agentic Security}},
  year    = {2025},
  url     = {https://nailinstitute.org/annual-report/2025},
  note    = {Inaugural edition}
}
```

To cite the AVE database:

```bibtex
@misc{nail_ave_database,
  title  = {AVE Database: Agentic Vulnerabilities \& Exposures},
  author = {{NAIL Institute for Agentic Security}},
  year   = {2025},
  url    = {https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/ave-database}
}
```

---

*Thank you to everyone who contributed to this inaugural edition of the
Annual AVE Report. The security of agentic AI systems is a collective
challenge that requires a collective response. Your contributions make
that response possible.*

*— The NAIL Institute for Agentic Security*

# 📈 NAIL Institute — Statistical Analysis (Summary)

> Subset of statistical analyses from the NAIL experimental programme.
> Full analysis available in the NAIL Paper (forthcoming).

---

## Experiment 2: Consensus Paralysis

**Control vs Escalation (rounds):**
- Mann-Whitney U = 90.0, **p = 0.000378 ★★★**
- Control: mean=27.4, median=30.0
- Escalation: mean=5.0, median=5.0
- Control 95% CI: [22.2, 30.0]
- Escalation 95% CI: [5.0, 5.0]

**Token savings:** 16.8× reduction with escalation intervention.

**Pairwise comparisons:**
| Comparison | U | p | Sig |
|-----------|---|---|-----|
| control vs escalation | 90.0 | 0.0008 | ★★★ |
| weighted_voting vs escalation | 80.0 | 0.0155 | ★ |
| escalation vs compromise | 10.0 | 0.0009 | ★★★ |
| control vs weighted_voting | 65.0 | 0.1494 | ns |
| control vs compromise | 55.0 | 0.5842 | ns |

## Experiment 2 @ 70B: Scale Comparison

- **Control 70B**: rounds mean=14.4, CI=[11.2, 17.6], **100% consensus** (vs 10% at 7B)
- Confirms capability-threshold hypothesis: consensus paralysis resolves at scale

## Confused Deputy — Cross-Model χ² Test

- **χ² p = 0.0002** (highly significant)
- Effect: Tool description exploitation is **model-dependent** but **universally present**
- Claude Sonnet 4 and Gemini 2.5 Pro: 100% exploitation
- Nemotron 70B: 17% exploitation
- Tool specificity: Output-producing tools exploited at 100%, input-analyzing at 0%

## Bystander Effect

- Solo vs Team decisive action: 100% vs 80%
- Response time inflation: 4.9× in team condition
- Layer 5 (Startle Response): eliminates gap entirely (100% both conditions)

---

*Full statistical analysis with bootstrap confidence intervals, effect sizes,
and power analyses available in the complete paper.*

*NAIL Institute — Neuravant AI Limited, 2026.*

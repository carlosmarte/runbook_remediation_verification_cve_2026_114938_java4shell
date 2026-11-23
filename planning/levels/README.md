# Plans by organisational level

The same programme, restated for each level of the organisation as the steps that level owns, the decisions it
makes, the evidence it reads and the report it receives. Each file is self-contained; cross-references point to the
category plans in `../` and the report templates in `../../report-template/`.

| Level | File | Owns | Reads |
| :--- | :--- | :--- | :--- |
| Executive (board, CISO, CIO, BU heads) | [executive.md](executive.md) | risk appetite, SLAs, budget, change windows, external statements | R0, R9 |
| Programme / security leadership | [programme.md](programme.md) | sequencing, RACI, scorecard, exceptions, escalation | R1, R2 |
| Engineering management (directors, EMs) | [engineering-management.md](engineering-management.md) | capacity, prioritisation across services, EOL migrations, gate adoption | R2, R5, R7 |
| Team / service owners | [team.md](team.md) | one service end to end: mitigate, trace, patch, prove | R3, R4, R6 |
| Engineer / operator (developer, SRE, SOC, edge) | [engineer-operator.md](engineer-operator.md) | the hands-on steps: commands, PRs, restarts, rules, triage | R4, R6, R8, R10 |

How to use: start at your level, follow its steps, and open the referenced category plan only when a step needs the
detail. Hand-offs between levels are explicit ("you receive … / you deliver …").

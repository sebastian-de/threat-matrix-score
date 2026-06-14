# threat-matrix-score

A small Python script that prioritises Kubernetes security mitigations from Microsoft's [Threat Matrix for Kubernetes](https://github.com/microsoft/Threat-Matrix-for-Kubernetes).

The script reads three CSV files describing the relevant threats, mitigations and the protection levels of the affected cluster components, and writes a sorted CSV listing which mitigations would yield the biggest risk reduction.

I wrote this script as part of my Master's thesis (link will be added once it's finished).

## Files

| File | Purpose | Source |
| --- | --- | --- |
| `threats.csv` | Threats from the Threat Matrix, plus user-supplied applicability. | Derived from the [Threat Matrix for Kubernetes](https://github.com/microsoft/Threat-Matrix-for-Kubernetes). |
| `mitigations.csv` | Mitigations from the Threat Matrix, plus user-supplied implementation status. | Derived from the [Threat Matrix for Kubernetes](https://github.com/microsoft/Threat-Matrix-for-Kubernetes). |
| `protection_levels.csv` | Confidentiality / integrity / availability rating per cluster component. | User-supplied. |
| `score.py` | The scoring script. | - |

## Input columns the user fills in

### `threats.csv`

- `applicable` (`true` / `false`): is this threat relevant to your setup?
  Non-applicable threats are ignored when scoring mitigations.

### `mitigations.csv`

- `built_in` (`true` / `false`): does the mitigation work with stock Kubernetes, without extra software? Surfaced in the output so quick wins can be picked first; does not affect the score.
- `implemented` (`true` / `false`): mitigations marked `true` are dropped from the CSV output so you only see what is still open.

### `protection_levels.csv`

- One row per cluster component referenced as `primary_component` in `threats.csv`, with a `high` / `medium` / `low` rating for confidentiality, integrity and availability.

## Usage

```bash
python3 score.py
```

## Scoring

Levels are mapped to numbers: `high = 3`, `medium = 2`, `low = 1`.

### Per-threat (default)

Each applicable threat is scored independently against each CIA dimension by taking the protection level of its `primary_component` for that dimension. The combined `score` is the maximum of the three:

```
score_c = pl[component].c
score_i = pl[component].i
score_a = pl[component].a
score   = max(score_c, score_i, score_a)
```

### Per-threat (with `apply_tactic_mapping = True`).

Each MITRE ATT&CK® tactic is also associated with a subset of CIA dimensions it typically targets (`tactic_impacts` in `scoring.py`):

| Tactic | Targets |
| --- | --- |
| `InitialAccess`, `Execution`, `PrivilegeEscalation`, `LateralMovement` | C, I, A |
| `Collection`, `CredentialAccess`, `Discovery` | C |
| `DefenseEvasion`, `Persistence` | I |
| `Impact` | I, A |

The dimensions a threat damages become the union over its tactics, and dimensions outside that set contribute zero. Narrow threats (e.g. a Collection-only threat against a high-confidentiality component) therefore score lower than broad ones:

```
affects = union(tactic_impacts[t] for t in threat.tactics)
score_c = pl[component].c if "c" in affects else 0     # same for i, a
score   = max(score_c, score_i, score_a)
```

Toggle this via the `apply_tactic_mapping` constant in `scoring.py`.

### Per-mitigation

For each mitigation that is not yet `implemented`, the result row's four scores are sums over the applicable threats it addresses:

```
score    = sum(threat.score   for each addressed applicable threat)
score_c  = sum(threat.score_c for each addressed applicable threat)
score_i  = sum(threat.score_i for each addressed applicable threat)
score_a  = sum(threat.score_a for each addressed applicable threat)
```

Mitigations that address only non-applicable threats are skipped. Output is sorted by `score` (descending), then by `threat_count` (descending), then by `mitigation_id`. The C/I/A sub-scores let you re-sort the list for an audience focused on a single dimension (e.g. compliance reviews fixated on confidentiality).

## Output

`scoring.csv` has one row per still-open mitigation that addresses at least one applicable threat:

| Column | Meaning |
| --- | --- |
| `mitigation_id`, `mitigation_name` | From `mitigations.csv`. |
| `built_in` | Copied through for quick filtering. |
| `score` | Sum of combined threat scores addressed by this mitigation. |
| `score_c`, `score_i`, `score_a` | Per-dimension sub-scores; re-sort by any to focus on confidentiality, integrity, or availability. |
| `threat_count` | Number of applicable threats the mitigation addresses. |
| `threats` | The contributing threats as `threat_id(score);...`. |

## Licensing

This repository combines original code with data adapted from a third-party work, so it carries two licenses.

### Code - MIT

- `scoring.py`
- `README.md`

### Data - CC BY 4.0

- `threats.csv`, `mitigations.csv`
- `protection_levels.csv` is original to this repository; it is offered under CC BY 4.0 alongside the matrix-derived data for consistency.

The threat and mitigation content is adapted from Microsoft's [Threat Matrix for Kubernetes](https://github.com/microsoft/Threat-Matrix-for-Kubernetes), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

#!/usr/bin/env python3

import csv
from pathlib import Path

base_dir = Path(__file__).parent
threats_csv = base_dir / "threats.csv"
mitigations_csv = base_dir / "mitigations.csv"
protection_levels_csv = base_dir / "protection_levels.csv"
scoring_csv = base_dir / "scoring.csv"

# Qualitative levels mapped to numeric weights.
levels = {"high": 3, "medium": 2, "low": 1}

# CIA dimension keys mapped to their protection_levels.csv column names.
cia_columns = {"c": "confidentiality", "i": "integrity", "a": "availability"}

# When this setting is enabled, the impact of each threat's CIA is limited to
# the intersection of its tactics' impact sets (see 'tactic_impacts' below).
# When set to False (the default setting), every threat affects all three dimensions.
apply_tactic_mapping = False

# CIA dimensions typically targeted by the respective MITRE tactic.
tactic_impacts = {
    "InitialAccess": {"c", "i", "a"},
    "Execution": {"c", "i", "a"},
    "PrivilegeEscalation": {"c", "i", "a"},
    "LateralMovement": {"c", "i", "a"},
    "Collection": {"c"},
    "CredentialAccess": {"c"},
    "Discovery": {"c"},
    "DefenseEvasion": {"i"},
    "Persistence": {"i"},
    "Impact": {"i", "a"},
}

fieldnames = [
    "mitigation_id",
    "mitigation_name",
    "built_in",
    "score",
    "score_c",
    "score_i",
    "score_a",
    "threat_count",
    "threats",
]


def level(value):
    """Convert a qualitative level string to its numeric weight."""
    return levels[value.strip().lower()]


def parse_bool(value):
    return value.strip().lower() == "true"


def threat_affects(threat_id, tactics_str):
    """Return the set of CIA dimensions a threat's tactics target."""
    if not apply_tactic_mapping:
        return cia_columns
    tactics = [t.strip() for t in tactics_str.split(";")]
    unknown = [t for t in tactics if t not in tactic_impacts]
    if unknown:
        raise KeyError(f"Threat {threat_id!r} has unknown tactic(s): {unknown}")
    return {d for t in tactics for d in tactic_impacts[t]}


def load_protection_levels(path):
    """Return {component: {"c": int, "i": int, "a": int}}."""
    with path.open(newline="", encoding="utf-8") as f:
        return {
            row["component"]: {dim: level(row[col]) for dim, col in cia_columns.items()}
            for row in csv.DictReader(f)
        }


def load_threats(path, protection_levels):
    """
    Load threats and pre-compute per-dimension scores. For each threat,
    `affects` is the set of CIA dimensions targeted by its tactics; its
    per-dimension score is the matching protection level (0 if not targeted)
    and `score` is the max of the three.
    """
    threats = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            component = row["primary_component"]
            if component not in protection_levels:
                raise KeyError(
                    f"Component {component!r} (threat {row['threat_id']}) "
                    f"has no protection_levels entry"
                )
            affects = threat_affects(row["threat_id"], row["tactics"])
            pl = protection_levels[component]
            row["applicable"] = parse_bool(row["applicable"])
            for dim in cia_columns:
                row[f"score_{dim}"] = pl[dim] if dim in affects else 0
            row["score"] = max(row["score_c"], row["score_i"], row["score_a"])
            threats.append(row)
    return threats


def load_mitigations(path):
    mitigations = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["built_in"] = parse_bool(row["built_in"])
            row["implemented"] = parse_bool(row["implemented"])
            row["threats"] = {t.strip() for t in row["threats"].split(";")}
            mitigations.append(row)
    return mitigations


def score_mitigations(threats, mitigations):
    """
    For each mitigation, sum per-dimension scores across the applicable threats
    it addresses. Mitigations that are already implemented, or that address
    only non-applicable threats, are excluded. Sorted by combined `score`
    (descending), then threat_count (descending), then mitigation_id.
    """
    applicable = {t["threat_id"]: t for t in threats if t["applicable"]}

    rows = []
    for m in mitigations:
        if m["implemented"]:
            continue
        covered = [
            (tid, applicable[tid]) for tid in sorted(m["threats"]) if tid in applicable
        ]
        if not covered:
            continue
        rows.append(
            {
                "mitigation_id": m["id"],
                "mitigation_name": m["name"],
                "built_in": str(m["built_in"]).lower(),
                "score": sum(t["score"] for _, t in covered),
                "score_c": sum(t["score_c"] for _, t in covered),
                "score_i": sum(t["score_i"] for _, t in covered),
                "score_a": sum(t["score_a"] for _, t in covered),
                "threat_count": len(covered),
                "threats": ";".join(f"{tid}({t['score']})" for tid, t in covered),
            }
        )

    rows.sort(key=lambda x: (-x["score"], -x["threat_count"], x["mitigation_id"]))
    return rows


def main():
    protection_levels = load_protection_levels(protection_levels_csv)
    threats = load_threats(threats_csv, protection_levels)
    mitigations = load_mitigations(mitigations_csv)
    rows = score_mitigations(threats, mitigations)

    with scoring_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Scoring for {len(rows)} mitigations written to {scoring_csv.name}.")


if __name__ == "__main__":
    main()

"""Versioned structured response contracts shared with durable replay."""

OBJECT_LISTS = {
    name: {
        "type": "object",
        "required": [name],
        "properties": {
            name: {"type": "array", "items": {"type": "object"}},
        },
    }
    for name in ("hypotheses", "verdicts", "findings")
}
DISCOVERY_SCHEMA = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["line", "snippet", "title"],
                "properties": {
                    "line": {"type": "integer", "minimum": 1},
                    "snippet": {"type": "string", "minLength": 12},
                    "title": {"type": "string", "minLength": 1},
                },
            },
        }
    },
}
VERDICT_SCHEMA = {
    "type": "object",
    "required": ["verdicts"],
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["verdict", "reason"],
                "properties": {
                    "verdict": {"type": "string", "enum": ["upheld", "refuted", "uncertain"]},
                    "reason": {"type": "string"},
                    "_claim_idx": {"type": "integer", "minimum": 0},
                    "_hyp_idx": {"type": "integer", "minimum": 0},
                },
            },
        }
    },
}


# Upheld answers must be complete enough to undergo the mechanical citation gate.
# Conditional/uncertain observations may legitimately contain partial evidence.
VERDICT_SCHEMA["properties"]["verdicts"]["items"]["allOf"] = [
    {
        "if": {"properties": {"verdict": {"const": "upheld"}}},
        "then": {
            "required": ["evidence", "reachability_assessment"],
            "properties": {
                "evidence": {
                    "type": "object",
                    "required": [
                        "attacker_control",
                        "path",
                        "sink",
                        "protection",
                        "protection_failure",
                        "impact",
                        "assumptions",
                    ],
                    "properties": {
                        **{
                            key: {"type": "string", "minLength": 1}
                            for key in (
                                "attacker_control",
                                "path",
                                "sink",
                                "protection",
                                "protection_failure",
                                "impact",
                            )
                        },
                        "assumptions": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "reachability_assessment": {
                    "type": "object",
                    "required": ["status", "entrypoint", "prerequisites"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": [
                                "reachable",
                                "conditional",
                                "no_demonstrated_caller",
                                "unresolved",
                            ],
                        },
                        "entrypoint": {"type": "string"},
                        "prerequisites": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        },
    }
]


HYPOTHESIS_SCHEMA = {
    "type": "object",
    "required": ["hypotheses"],
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["rule_id", "file", "line", "exploitability"],
                "properties": {
                    "rule_id": {"type": "string", "minLength": 1},
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 0},
                    "exploitability": {
                        "type": "string",
                        "enum": ["confirmed", "likely", "possible", "false_positive"],
                    },
                },
            },
        }
    },
}

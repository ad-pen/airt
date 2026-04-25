from __future__ import annotations

from dataclasses import dataclass, field

OWASP_LLM_TOP10: dict[str, dict] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": (
            "Attackers craft inputs that override or hijack the model's instructions, "
            "causing it to perform unintended actions."
        ),
        "attack_classes": ["prompt-injection", "indirect-injection"],
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": (
            "LLM output is passed downstream without validation, enabling XSS, SSRF, "
            "privilege escalation, or remote code execution."
        ),
        "attack_classes": ["jailbreak", "role-confusion"],
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": (
            "Malicious data introduced into training or fine-tuning pipelines causes "
            "the model to learn backdoors or biased behaviors."
        ),
        "attack_classes": ["rag-poisoning"],
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": (
            "Inputs that cause the model to consume excessive resources, degrading "
            "availability for legitimate users."
        ),
        "attack_classes": [],
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Risks from third-party models, datasets, or plugins that may be compromised "
            "or malicious."
        ),
        "attack_classes": [],
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": (
            "The model reveals confidential data such as PII, credentials, or proprietary "
            "business information in its responses."
        ),
        "attack_classes": ["data-extraction"],
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": (
            "Plugins or tools invoked by the LLM lack proper access controls, enabling "
            "attackers to abuse their functionality."
        ),
        "attack_classes": ["agentic-exploitation"],
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": (
            "The LLM is granted too much autonomy or capability, allowing it to take "
            "harmful actions with real-world consequences."
        ),
        "attack_classes": ["agentic-exploitation"],
    },
    "LLM09": {
        "name": "Overreliance",
        "description": (
            "Users or systems trust LLM outputs without verification, leading to "
            "decisions based on hallucinated or manipulated content."
        ),
        "attack_classes": ["policy-bypass"],
    },
    "LLM10": {
        "name": "Model Theft",
        "description": (
            "Attackers extract model weights, architecture, or training data through "
            "repeated queries or side-channel techniques."
        ),
        "attack_classes": [],
    },
}


@dataclass
class OwaspEntry:
    id: str
    name: str
    description: str
    attack_classes: list[str]
    payload_count: int = 0
    covered: bool = False


def coverage_report(payloads: list) -> list[OwaspEntry]:
    """Given a list of Payload objects, return coverage per OWASP entry."""
    entries: list[OwaspEntry] = []
    for owasp_id, info in OWASP_LLM_TOP10.items():
        count = sum(
            1 for p in payloads
            if str(p.attack_class.value if hasattr(p.attack_class, "value") else p.attack_class)
            in info["attack_classes"]
        )
        entries.append(
            OwaspEntry(
                id=owasp_id,
                name=info["name"],
                description=info["description"],
                attack_classes=list(info["attack_classes"]),
                payload_count=count,
                covered=count > 0,
            )
        )
    return entries


def owasp_for_class(attack_class: str) -> list[str]:
    """Return list of OWASP IDs that this attack_class maps to."""
    return [
        owasp_id
        for owasp_id, info in OWASP_LLM_TOP10.items()
        if attack_class in info["attack_classes"]
    ]

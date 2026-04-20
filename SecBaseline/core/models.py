from dataclasses import asdict, dataclass


@dataclass
class Rule:
    rule_id: str
    name: str
    module: str
    rule_type: str
    severity: str
    key: str | None = None
    expected: object | None = None
    target: str | None = None
    target_type: str | None = None
    data_key: str | None = None
    operator: str | None = None
    needle: str | None = None
    profiles: list[str] | None = None
    compliance: list[str] | None = None
    recommendation: str = ""


@dataclass
class CheckResult:
    rule_id: str
    name: str
    module: str
    status: str
    severity: str
    message: str
    evidence: str
    compliance: list[str] | None = None
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

from __future__ import annotations

from dataclasses import dataclass, field

from airt.models import SessionResult, Status


@dataclass
class DiffEntry:
    payload_id: str
    old_status: Status | None
    new_status: Status | None

    @property
    def change(self) -> str:
        if self.old_status is None:
            return "added"
        if self.new_status is None:
            return "removed"
        if self.old_status == self.new_status:
            return "unchanged"
        if self.new_status == Status.LIKELY_SUCCESS and self.old_status != Status.LIKELY_SUCCESS:
            return "regression"
        if self.old_status == Status.LIKELY_SUCCESS and self.new_status != Status.LIKELY_SUCCESS:
            return "fixed"
        return "changed"


@dataclass
class DiffResult:
    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def regressions(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "regression"]

    @property
    def fixes(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "fixed"]

    @property
    def added(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "added"]

    @property
    def removed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "removed"]

    @property
    def changed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "changed"]

    @property
    def unchanged(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "unchanged"]


def _best_status(sessions: list[SessionResult]) -> dict[str, Status]:
    best: dict[str, Status] = {}
    for s in sessions:
        pid = s.payload_id
        if pid not in best:
            best[pid] = s.overall_status
        else:
            if _status_rank(s.overall_status) > _status_rank(best[pid]):
                best[pid] = s.overall_status
    return best


_RANK = {
    Status.ERROR: 0,
    Status.NO_SIGNAL: 1,
    Status.DEFLECTED: 2,
    Status.FLAGS_PRESENT: 3,
    Status.LIKELY_SUCCESS: 4,
}


def _status_rank(s: Status) -> int:
    return _RANK.get(s, 0)


def diff_sessions(
    old_sessions: list[SessionResult],
    new_sessions: list[SessionResult],
) -> DiffResult:
    old_map = _best_status(old_sessions)
    new_map = _best_status(new_sessions)

    all_ids = sorted(set(old_map) | set(new_map))
    entries = []
    for pid in all_ids:
        entries.append(
            DiffEntry(
                payload_id=pid,
                old_status=old_map.get(pid),
                new_status=new_map.get(pid),
            )
        )
    return DiffResult(entries=entries)

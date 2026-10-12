"""Structured scopes: plain-English rendering + coverage checks.

Scopes are machine-checkable JSON (RAR-inspired). The verifier uses
`covers()` to decide whether a requested action fits the granted scope.
"""


def describe(scope: dict) -> str:
    """Render a scope in plain English for the approval ceremony."""
    action = scope.get("action")
    if action == "book_lodging":
        parts = ["Book lodging"]
        if scope.get("max_total_usd") is not None:
            parts.append(f"up to ${scope['max_total_usd']:,}")
        if scope.get("area"):
            parts.append(f"in {scope['area']}")
        if scope.get("dates"):
            parts.append(f"for {scope['dates'][0]} to {scope['dates'][1]}")
        if scope.get("guests"):
            parts.append(f"({scope['guests']} guests)")
        text = " ".join(parts) + "."
        if scope.get("non_refundable_ok") is False:
            text += " Refundable rates only."
        return text
    if action == "read_calendar":
        return "Read calendar events."
    # Fallback: summarize generically so unknown actions are never vague.
    details = ", ".join(f"{k}={v}" for k, v in scope.items() if k != "action")
    return f"Perform '{action}' ({details})."


def scope_class(scope: dict) -> str:
    """Coarse class used for standing policies (e.g. remember approvals)."""
    return str(scope.get("action", "unknown"))


def covers(granted: dict, requested_action: str, requested: dict) -> tuple[bool, str]:
    """Does the granted scope cover the requested action? Returns (ok, reason)."""
    if granted.get("action") != requested_action:
        return False, f"scope action {granted.get('action')!r} != {requested_action!r}"
    if requested_action == "book_lodging":
        max_total = granted.get("max_total_usd")
        if max_total is not None and requested.get("total_usd", 0) > max_total:
            return False, f"${requested.get('total_usd')} exceeds scope max ${max_total}"
        area = granted.get("area")
        if area and area.lower() not in str(requested.get("area", "")).lower():
            return False, f"area {requested.get('area')!r} outside scope {area!r}"
        return True, "within scope"
    # Unknown actions: deny by default (fail closed).
    return False, f"no coverage rule for action {requested_action!r}"


def narrows(child: dict, parent: dict) -> tuple[bool, str]:
    """Is the child scope equal-or-narrower than the parent? (for sub-agents)"""
    if child.get("action") != parent.get("action"):
        return False, "action mismatch"
    for key in ("max_total_usd",):
        if key in child and key in parent and child[key] > parent[key]:
            return False, f"{key}={child[key]} wider than parent {parent[key]}"
    return True, "narrower-or-equal"

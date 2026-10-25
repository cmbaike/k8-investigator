"""Application-written disclosure of what an investigation was asked to cover
and what it actually covered.

Fixed wording over application-derived values only (names that passed DNS-1123
validation, counts). Nothing here comes from a model.
"""

from app.reports.snapshot import SnapshotScope

MAX_NAMES_SHOWN = 5


def _names(names) -> str:
    shown = ", ".join(repr(n) for n in names[:MAX_NAMES_SHOWN])
    more = len(names) - MAX_NAMES_SHOWN

    return shown + (f" and {more} more" if more > 0 else "")


def _requested(scope: SnapshotScope) -> str:
    kind = f"{scope.requested_kind} " if scope.requested_kind else "workload "

    return f"{kind}{scope.requested!r}"


def limitation_text(scope: SnapshotScope | None) -> str | None:
    """Why a targeted investigation could not examine its target, else None."""
    if scope is None or not scope.targeted or scope.resolved:
        return None

    requested = _requested(scope)

    if scope.status == "not_found":
        return (
            f"The requested {requested} could not be found: none of the "
            f"{scope.listed} pod(s) listed in the namespace is controlled by a "
            "workload with that name. No other workload was investigated in "
            "its place. It may not exist, may be named differently, or may "
            "currently have no pods."
        )

    if scope.status == "ambiguous":
        return (
            f"The requested {requested} matches more than one workload in the "
            "namespace, so none was investigated. Name the workload kind to "
            "disambiguate."
        )

    if scope.status == "unverifiable":
        return (
            f"The requested {requested} could not be resolved: the owning "
            f"workload of {scope.unverified} of {scope.listed} listed pod(s) "
            "could not be verified. No other workload was investigated in "
            "its place."
        )

    return (
        f"The requested {requested} could not be resolved because the "
        "namespace's pods were not listed. Nothing was investigated."
    )


def scope_summary_line(scope: SnapshotScope | None) -> str | None:
    """One line stating the target (or the coverage of a broad question)."""
    if scope is None:
        return None

    if scope.targeted:
        limitation = limitation_text(scope)

        if limitation is not None:
            return f"Target: {limitation}"

        others = max(0, scope.listed - len(scope.pods))

        return (
            f"Target: {scope.workload_kind} {scope.workload_name!r}, verified "
            "through Kubernetes owner references. Inspected only its "
            f"{len(scope.pods)} pod(s): {_names(scope.pods)}. The other "
            f"{others} pod(s) listed in the namespace were not inspected."
        )

    if scope.listed:
        basis = (
            "the question asked about the namespace as a whole"
            if scope.broad_explicit
            else "no workload name was recognised in the question, so the "
            "whole namespace was in scope; name a workload exactly to "
            "investigate only that workload"
        )

        return (
            f"Coverage: a namespace-level investigation ({basis}). "
            f"{scope.listed} pod(s) were listed and "
            f"{scope.inspected} health-inspected."
        )

    return None


def rejection_text(scope: SnapshotScope | None) -> str | None:
    """Disclosure of model proposals refused outside the bound workload."""
    if scope is None or scope.rejected_proposals == 0:
        return None

    reasons = ", ".join(scope.rejected_reasons)

    return (
        f"{scope.rejected_proposals} tool call(s) proposed by the AI model were "
        "refused before execution because they were outside the requested "
        f"workload (reason: {reasons}). None was executed; each refusal is "
        "recorded in the investigation audit trail."
    )


def scope_uncertainties(scope: SnapshotScope | None) -> list[str]:
    """Limitations for the report's uncertainty list (first, never dropped)."""
    items: list[str] = []
    limitation = limitation_text(scope)

    if limitation is not None:
        items.append(limitation)
    elif scope is not None and not scope.targeted and scope.listed > scope.inspected:
        items.append(
            f"Namespace-level coverage: {scope.inspected} of {scope.listed} "
            "listed pod(s) were health-inspected; the rest were not examined."
        )

    rejection = rejection_text(scope)

    if rejection is not None:
        items.append(rejection)

    return items


def scope_checks(scope: SnapshotScope | None) -> list[str]:
    """Read-only next steps when a targeted investigation could not proceed."""
    if limitation_text(scope) is None:
        return []

    return [
        f"Confirm the exact name of the {_requested(scope)} and the namespace "
        "it runs in, using a read-only listing of workloads or pods.",
        "Re-run naming the confirmed workload, or ask a broad question about "
        "the namespace to review every pod in it.",
    ]

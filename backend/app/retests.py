"""Classify exact-template retests using their own observed output and telemetry."""
from urllib.parse import urlsplit

from .importers import ParseResult, web_identity


def evaluate_retest(template_id: str, target: str, parsed: ParseResult, progress: dict,
                    initial_status: int | None, *, expected_match: str | None = None,
                    source_known: bool = True) -> dict:
    identity = web_identity(expected_match or target)
    matches = [
        finding for record in parsed.records
        if (finding := record.finding) and finding["template_id"] == template_id and identity
        and web_identity(finding["matched_at"]) == identity
    ]
    if matches:
        matchers = {finding["evidence"].get("matcher-name") for finding in matches}
        return {"outcome": "reproduced", "reason": "The template matched the original route.",
                "matchers": sorted(matcher for matcher in matchers if matcher)}

    if not source_known:
        route = urlsplit(expected_match or target)
        if route.path not in {"", "/"} or route.query:
            return {"outcome": "inconclusive", "reason": "The original scanner input for this route was not retained."}

    try:
        templates = int(progress["templates"])
        requests = int(progress["requests"])
        total = int(progress["total"])
        errors = int(progress["errors"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return {"outcome": "inconclusive", "reason": "The scanner did not report complete execution counters."}
    if (templates != 1 or not 0 < total <= requests or errors != 0 or parsed.warnings
            or not initial_status or not 200 <= initial_status < 300):
        return {"outcome": "inconclusive", "reason": "The original route or full template execution could not be verified.",
                "requests": requests, "errors": errors}
    if any(record.finding for record in parsed.records):
        return {"outcome": "inconclusive", "reason": "The scanner matched a different route or template.",
                "requests": requests, "errors": errors}
    return {"outcome": "not_reproduced", "reason": "The exact template completed and did not match this time.",
            "requests": requests, "errors": errors}

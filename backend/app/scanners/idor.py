"""Controlled detector for Broken Access Control / Insecure Direct Object Reference.

Two synthetic laboratory accounts are used. Each one authenticates and reads its
own object to establish what a legitimate response looks like, then User A
requests User B's object with User A's session. A finding is confirmed only when
the response A receives is attributable to B — either through an explicit owner
field or because the representation matches B's own view of the object and not
A's. Requests are read-only by design: the detector never writes, modifies, or
deletes an object belonging to either account, so a target's seeded state is
unchanged by a scan.

An unauthenticated control request against the same object separates a genuine
object-level authorization flaw from an endpoint that simply serves public data,
and that distinction is recorded in the evidence.

The bundled Juice Shop preset provisions two `@lab.invalid` accounts through the
documented registration API (only if they do not already exist) and compares
their shopping baskets. Other authorized applications can supply their own login
flow, account pair, object path template, and owner field through
ScanContext.extra.
"""

from __future__ import annotations

import hashlib
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any
from urllib.parse import ParseResult, quote, urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "login_username_field": "username",
    "login_password_field": "password",
    "login_request_style": "form",
    "register_request_style": "json",
    "object_request_method": "GET",
    "evidence_body_limit": 400,
}

LAB_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "login_path": "/rest/user/login",
        "login_username_field": "email",
        "login_password_field": "password",
        "login_request_style": "json",
        "token_json_path": "authentication.token",
        "token_header": "Authorization",
        "token_cookie": "token",
        "object_id_json_path": "authentication.bid",
        "object_path_template": "/rest/basket/{object_id}",
        "owner_marker_json_path": "data.UserId",
        "register_path": "/api/Users/",
        "register_request_style": "json",
        "register_password_repeat_field": "passwordRepeat",
        "register_extra_fields": {
            "securityQuestion": {"id": 1},
            "securityAnswer": "vulnvista lab",
        },
        "user_a_username": "vulnvista.idor.a@lab.invalid",
        "user_a_password": "VulnVistaLabA1!",
        "user_b_username": "vulnvista.idor.b@lab.invalid",
        "user_b_password": "VulnVistaLabB1!",
    }
}
LAB_PRESETS["vulnvista_juice_shop"] = LAB_PRESETS["juice-shop"]

# The detector only ever reads. Anything that could change or destroy a
# laboratory object is rejected before a request is sent.
READ_ONLY_METHODS = {"GET", "HEAD"}


class DetectorError(Exception):
    """Expected, actionable detector failure shown directly to the operator."""


@dataclass
class ObjectProbe:
    """One read of an object, reduced to the fields the verdict depends on."""

    status_code: int
    owner_marker: str | None = None
    body_hash: str | None = None
    body_snippet: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str


def get_nested(mapping: Any, dotted_path: str) -> Any:
    """Safely retrieve a dotted field from JSON-like dictionaries."""
    current = mapping
    for key in dotted_path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def attribute_owner(cross: ObjectProbe, a_own: ObjectProbe, b_own: ObjectProbe) -> str:
    """Decide whose object User A actually received back.

    An explicit owner field is the strongest signal and is preferred whenever the
    target exposes one. Otherwise the returned representations are compared: if
    what A received matches B's own view and differs from A's own view, the
    object A read belongs to B.
    """
    markers = (cross.owner_marker, a_own.owner_marker, b_own.owner_marker)
    if all(marker is not None for marker in markers):
        if cross.owner_marker == a_own.owner_marker:
            return "same_user"
        if cross.owner_marker == b_own.owner_marker:
            return "other_user"
        return "unknown"

    if a_own.body_hash is not None and a_own.body_hash == b_own.body_hash:
        # The two accounts' objects look identical, so no comparison can
        # establish ownership either way.
        return "indistinguishable"
    if cross.body_hash == a_own.body_hash:
        return "same_user"
    if cross.body_hash == b_own.body_hash:
        return "other_user"
    return "unknown"


def classify(cross: ObjectProbe, ownership: str, unauthenticated_ok: bool) -> Decision:
    """Convert the cross-account read into the shared verdict."""
    if not cross.ok:
        return Decision(
            detected=False,
            validation_status="NOT_DETECTED",
            confidence="LOW",
            severity="INFO",
            reason=(
                "the second account's object was refused to the first account with "
                f"HTTP {cross.status_code}"
            ),
        )

    if ownership == "other_user":
        exposure = (
            "and the same object is served without any authentication at all"
            if unauthenticated_ok
            else "while an unauthenticated request for it is refused"
        )
        return Decision(
            detected=True,
            validation_status="CONFIRMED",
            confidence="HIGH",
            severity="HIGH",
            reason=(
                "the first account read the object owned by the second account "
                f"and received that account's data {exposure}"
            ),
        )

    if ownership == "same_user":
        return Decision(
            detected=False,
            validation_status="NOT_DETECTED",
            confidence="LOW",
            severity="INFO",
            reason=(
                "the target ignored the supplied identifier and returned the "
                "requesting account's own object"
            ),
        )

    if ownership == "indistinguishable":
        return Decision(
            detected=False,
            validation_status="INCONCLUSIVE",
            confidence="LOW",
            severity="INFO",
            reason=(
                "both accounts' objects returned identical representations, so ownership "
                "of the response could not be attributed; configure "
                "'owner_marker_json_path' or seed distinguishable data for each account"
            ),
        )

    return Decision(
        detected=True,
        validation_status="SUSPECTED",
        confidence="MEDIUM",
        severity="MEDIUM",
        reason=(
            "the first account received HTTP "
            f"{cross.status_code} for the second account's object and the response "
            "differed from its own, but ownership of the content could not be confirmed"
        ),
    )


class IDORDetector(BaseDetector):
    detector_id = "idor"
    name = "Broken Access Control / IDOR"
    vulnerability_type = "idor"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return self._error_result(context, "Target must be an absolute HTTP(S) URL.")

        host = parsed.hostname or ""
        origin = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        source = (
            "explicit configuration"
            if "object_path_template" in context.extra
            else "lab preset"
            if host in LAB_PRESETS
            else None
        )

        template = str(cfg.get("object_path_template") or "")
        if not template:
            return self._error_result(
                context,
                "No owner-scoped object is known for this target. Provide "
                "'object_path_template' (containing the '{object_id}' placeholder), the two "
                "accounts ('user_a_username'/'user_a_password' and "
                "'user_b_username'/'user_b_password'), and the login configuration in the "
                "target's scan configuration.",
            )
        if "{object_id}" not in template:
            return self._error_result(
                context, "'object_path_template' must contain the '{object_id}' placeholder."
            )
        method = str(cfg["object_request_method"]).upper()
        if method not in READ_ONLY_METHODS:
            return self._error_result(
                context,
                "This detector is read-only by design; 'object_request_method' must be "
                f"one of {', '.join(sorted(READ_ONLY_METHODS))}.",
            )
        if not cfg.get("login_path"):
            return self._error_result(
                context, "'login_path' is required so each account can obtain its own session."
            )

        try:
            async with AsyncExitStack() as stack:
                client_a = await stack.enter_async_context(self._new_client(cfg))
                client_b = await stack.enter_async_context(self._new_client(cfg))
                anonymous = await stack.enter_async_context(self._new_client(cfg, anonymous=True))

                object_id_a, provisioned_a = await self._establish_session(
                    client_a, origin, cfg, "a"
                )
                object_id_b, provisioned_b = await self._establish_session(
                    client_b, origin, cfg, "b"
                )
                if object_id_a == object_id_b:
                    raise DetectorError(
                        "Both accounts resolved to the same object id "
                        f"('{object_id_a}'), so cross-account access cannot be tested. "
                        "Check that the two configured accounts are distinct."
                    )

                url_a = self._object_url(origin, parsed, template, object_id_a)
                url_b = self._object_url(origin, parsed, template, object_id_b)

                a_own = await self._probe(client_a, url_a, method, cfg)
                if not a_own.ok:
                    raise DetectorError(
                        f"The first account could not read its own object at {url_a} "
                        f"(HTTP {a_own.status_code}); no legitimate baseline could be "
                        "established, so a cross-account result would be meaningless."
                    )
                b_own = await self._probe(client_b, url_b, method, cfg)
                if not b_own.ok:
                    raise DetectorError(
                        f"The second account could not read its own object at {url_b} "
                        f"(HTTP {b_own.status_code}); there is no owned object to attempt "
                        "unauthorised access against."
                    )

                unauthenticated = await self._probe(anonymous, url_b, method, cfg)
                cross = await self._probe(client_a, url_b, method, cfg)

            ownership = attribute_owner(cross, a_own, b_own)
            unauthenticated_ok = unauthenticated.ok and unauthenticated.body_hash == b_own.body_hash
            decision = classify(cross, ownership, unauthenticated_ok)
            return self._result(
                decision=decision,
                ownership=ownership,
                endpoint=url_b,
                object_id_a=object_id_a,
                object_id_b=object_id_b,
                a_own=a_own,
                b_own=b_own,
                cross=cross,
                unauthenticated=unauthenticated,
                unauthenticated_ok=unauthenticated_ok,
                source=source,
                method=method,
                provisioned=[
                    label
                    for label, was_provisioned in (("a", provisioned_a), ("b", provisioned_b))
                    if was_provisioned
                ],
            )
        except (httpx.HTTPError, DetectorError, ValueError) as exc:
            return self._error_result(context, f"{type(exc).__name__}: {exc}")

    def _new_client(self, cfg: dict[str, Any], anonymous: bool = False) -> httpx.AsyncClient:
        """Build one isolated client, so the two accounts never share a session."""
        return httpx.AsyncClient(
            timeout=cfg["request_timeout"],
            follow_redirects=True,
            cookies={} if anonymous else dict(cfg.get("cookies", {})),
            headers={} if anonymous else dict(cfg.get("headers", {})),
        )

    async def _establish_session(
        self, client: httpx.AsyncClient, origin: str, cfg: dict[str, Any], label: str
    ) -> tuple[str, bool]:
        """Log the account in (registering it first if permitted) and resolve its object id."""
        username = cfg.get(f"user_{label}_username")
        password = cfg.get(f"user_{label}_password")
        if not username or not password:
            raise DetectorError(
                f"Account '{label}' is not configured; provide 'user_{label}_username' and "
                f"'user_{label}_password'."
            )

        provisioned = False
        response = await self._login(client, origin, cfg, str(username), str(password))
        if response.status_code >= 400:
            if not cfg.get("register_path"):
                raise DetectorError(
                    f"Login failed for account '{label}' with HTTP {response.status_code}. "
                    "Provide working credentials, or a 'register_path' so the detector can "
                    "create its own synthetic accounts."
                )
            await self._register(client, origin, cfg, str(username), str(password), label)
            provisioned = True
            response = await self._login(client, origin, cfg, str(username), str(password))
            if response.status_code >= 400:
                raise DetectorError(
                    f"Account '{label}' could not log in (HTTP {response.status_code}) even "
                    "after registration."
                )

        payload = self._json_or_error(response, f"login response for account '{label}'")
        self._apply_token(client, cfg, payload, label)

        explicit_id = cfg.get(f"user_{label}_object_id")
        if explicit_id is not None:
            return str(explicit_id), provisioned

        id_path = cfg.get("object_id_json_path")
        if not id_path:
            raise DetectorError(
                "No object id is available. Provide 'object_id_json_path' (read from the "
                f"login response) or an explicit 'user_{label}_object_id'."
            )
        object_id = get_nested(payload, str(id_path))
        if object_id is None or object_id == "":
            raise DetectorError(
                f"The login response for account '{label}' did not contain the object id "
                f"field '{id_path}'."
            )
        return str(object_id), provisioned

    async def _login(
        self,
        client: httpx.AsyncClient,
        origin: str,
        cfg: dict[str, Any],
        username: str,
        password: str,
    ) -> httpx.Response:
        login_url = urljoin(f"{origin}/", str(cfg["login_path"]).lstrip("/"))
        credentials = {
            str(cfg["login_username_field"]): username,
            str(cfg["login_password_field"]): password,
        }
        if str(cfg["login_request_style"]).lower() == "json":
            return await client.post(login_url, json=credentials)
        return await client.post(login_url, data=credentials)

    async def _register(
        self,
        client: httpx.AsyncClient,
        origin: str,
        cfg: dict[str, Any],
        username: str,
        password: str,
        label: str,
    ) -> None:
        """Create one synthetic account. Only ever called for a configured account
        whose login already failed, and only when the target explicitly opts in by
        providing 'register_path'."""
        register_url = urljoin(f"{origin}/", str(cfg["register_path"]).lstrip("/"))
        payload: dict[str, Any] = {
            str(cfg.get("register_username_field", cfg["login_username_field"])): username,
            str(cfg.get("register_password_field", cfg["login_password_field"])): password,
        }
        repeat_field = cfg.get("register_password_repeat_field")
        if repeat_field:
            payload[str(repeat_field)] = password
        extra_fields = cfg.get("register_extra_fields")
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)

        if str(cfg["register_request_style"]).lower() == "json":
            response = await client.post(register_url, json=payload)
        else:
            response = await client.post(register_url, data=payload)
        if response.status_code >= 400:
            raise DetectorError(
                f"Could not provision synthetic account '{label}' at {register_url} "
                f"(HTTP {response.status_code})."
            )

    def _apply_token(
        self, client: httpx.AsyncClient, cfg: dict[str, Any], payload: Any, label: str
    ) -> None:
        """Attach the session credential returned by login to this account's client."""
        token_path = cfg.get("token_json_path")
        if not token_path:
            # Cookie-based sessions are already held by the client's cookie jar.
            return
        token = get_nested(payload, str(token_path))
        if not isinstance(token, str) or not token:
            raise DetectorError(
                f"The login response for account '{label}' did not contain token field "
                f"'{token_path}'."
            )
        if cfg.get("token_cookie"):
            client.cookies.set(str(cfg["token_cookie"]), token)
        if cfg.get("token_header"):
            header = str(cfg["token_header"])
            prefix = str(cfg.get("token_header_prefix", "Bearer "))
            client.headers[header] = f"{prefix}{token}"

    def _object_url(
        self, origin: str, target: ParseResult, template: str, object_id: str
    ) -> str:
        """Resolve the object template for one id, keeping the request on the
        authorized target's own origin."""
        raw = template.replace("{object_id}", quote(str(object_id), safe=""))
        url = (
            raw
            if urlparse(raw).scheme in {"http", "https"}
            else urljoin(f"{origin}/", raw.lstrip("/"))
        )
        parsed = urlparse(url)
        if parsed.scheme != target.scheme or parsed.netloc.lower() != target.netloc.lower():
            raise DetectorError(
                "The object path must resolve to the same origin as the authorized target."
            )
        return url

    async def _probe(
        self, client: httpx.AsyncClient, url: str, method: str, cfg: dict[str, Any]
    ) -> ObjectProbe:
        """Read one object and reduce the response to comparable evidence."""
        response = await client.request(method, url)
        body = response.text or ""
        marker: Any = None
        marker_path = cfg.get("owner_marker_json_path")
        if marker_path:
            try:
                marker = get_nested(response.json(), str(marker_path))
            except ValueError:
                marker = None
        limit = int(cfg["evidence_body_limit"])
        return ObjectProbe(
            status_code=response.status_code,
            owner_marker=None if marker is None else str(marker),
            body_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            body_snippet=body[:limit],
        )

    @staticmethod
    def _json_or_error(response: httpx.Response, what: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise DetectorError(f"The {what} was not valid JSON.") from exc

    def _result(
        self,
        decision: Decision,
        ownership: str,
        endpoint: str,
        object_id_a: str,
        object_id_b: str,
        a_own: ObjectProbe,
        b_own: ObjectProbe,
        cross: ObjectProbe,
        unauthenticated: ObjectProbe,
        unauthenticated_ok: bool,
        source: str | None,
        method: str,
        provisioned: list[str],
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter="object_id",
            description=(
                "The application authorises requests by the object identifier supplied by the "
                "caller rather than by the session's ownership of that object, so any "
                "authenticated user can read another user's records by changing the "
                "identifier in the request."
            ),
            evidence_summary=(
                f"{decision.reason}. Own object {object_id_a}: HTTP {a_own.status_code}; "
                f"other account's object {object_id_b}: HTTP {cross.status_code}."
            ),
            evidence={
                "request_method": method,
                "read_only": True,
                "ownership_attribution": ownership,
                "own_object": {
                    "object_id": object_id_a,
                    "status_code": a_own.status_code,
                    "owner_marker": a_own.owner_marker,
                    "body_sha256": a_own.body_hash,
                    "body_snippet": a_own.body_snippet,
                },
                "other_account_object_as_owner": {
                    "object_id": object_id_b,
                    "status_code": b_own.status_code,
                    "owner_marker": b_own.owner_marker,
                    "body_sha256": b_own.body_hash,
                },
                "other_account_object_as_first_account": {
                    "object_id": object_id_b,
                    "status_code": cross.status_code,
                    "owner_marker": cross.owner_marker,
                    "body_sha256": cross.body_hash,
                    "body_snippet": cross.body_snippet,
                },
                "cross_response_matches_owner_view": cross.body_hash == b_own.body_hash,
                "unauthenticated_control": {
                    "status_code": unauthenticated.status_code,
                    "served_owner_data": unauthenticated_ok,
                },
                "synthetic_accounts_provisioned": provisioned,
                "configuration_source": source,
                "cvss_vector": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    if unauthenticated_ok
                    else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                ),
            },
            remediation=(
                "Authorise every request against the session's own identity rather than an "
                "identifier supplied by the caller: look the object up scoped to the "
                "authenticated user, or verify ownership server-side before returning or "
                "modifying it. Apply the same check to every verb on the resource, deny by "
                "default, and keep the check server-side. Unpredictable identifiers (UUIDs) "
                "reduce discovery but are not an access-control mechanism on their own."
            ),
            cwe="CWE-639",
            cvss_score=(
                (7.5 if unauthenticated_ok else 6.5)
                if decision.validation_status == "CONFIRMED"
                else 5.3
                if decision.detected
                else 0.0
            ),
            owasp_category="A01:2021 - Broken Access Control",
        )

    def _error_result(self, context: ScanContext, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=context.base_url,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-639",
            owasp_category="A01:2021 - Broken Access Control",
        )

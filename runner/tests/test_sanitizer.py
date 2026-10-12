r"""The planted-secret suite: a sanitiser that misses a secret, or a seal that ships one (T-41).

``docs/protocols/data-management.md`` §5 requires the bundle sanitised before seal and unit-tested
with planted secrets, and states the consequence that gives the test its teeth: "a bundle failing
the planted-secret test cannot seal." These tests plant each of the four secret classes §5 names,
prove the sanitiser removes or redacts every one and that the scan then finds nothing, prove a JWT
keeps its claims while losing its signature, and prove a secret the sanitiser cannot rewrite -- one
in a structured file it does not touch -- refuses the seal. Bundles are built under ``tmp_path``,
never ``runs/``.
"""

import pytest

from runner.bundle import SealError, seal_bundle
from runner.manifest import RunManifest
from runner.sanitize import marker_for, sanitize_text, scan_for_secrets

_FIXED_SEALED_AT = "2026-08-27T00:00:00+00:00"

_PROBES_CSV = (
    "ts,probe_id,target,method,status_code,latency_ms,ok,error\n"
    "2026-08-27T00:00:00Z,probe-cart,/cart,GET,200,12.3,true,\n"
)
_RESOURCES_CSV = (
    "ts,series,namespace,workload,container,cpu_cores,mem_bytes,storage_bytes,restarts_total\n"
    "2026-08-27T00:00:00Z,framework,default,cartservice,server,0.10,1048576,2048,0\n"
)
_LOCUST_CSV = "name,requests,failures,median_ms,p95_ms\naggregated,1000,0,10,25\n"


def _compact_jws(header_json: str, *, signature: str = "S" * 43) -> str:
    """One compact JWS with ``header_json`` as its header, base64url-encoded as an encoder would.

    The header text is a parameter because the sanitiser's anchor is a property of the *encoding* of
    a JSON object, and encoders differ in whitespace: PyJWT emits ``{"alg":...}``, a pretty-printing
    one may emit ``{ "alg": ... }`` or a newline. Each encodes to a different two-character opening,
    and every one of them must still be recognised as a token.
    """
    import base64
    import json as _json

    def b64u(text: str) -> str:
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

    payload = b64u(_json.dumps({"sub": "executor-RUN-X", "jti": "abc", "run_id": "RUN-X"}))
    return f"{b64u(header_json)}.{payload}.{signature}"


# One per encoder shape, so the anchor is pinned against the encoding rather than against PyJWT.
_JWS_HEADER_SHAPES = (
    '{"alg":"HS256","typ":"JWT"}',
    '{ "alg": "HS256", "typ": "JWT" }',
    '{\n  "alg": "RS512"\n}',
    '{"typ":"JWT"}',
)

# Dotted identifiers that appear in this project's own evidence and must survive the sanitiser. The
# first is the one that reached a sealed bundle redacted; see runner/sanitize.py's docstring.
_DOTTED_IDENTIFIERS_THAT_ARE_NOT_TOKENS = (
    "rbac.authorization.k8s.io",
    "frontend.boutique.svc.cluster.local",
    "kubernetes.default.svc",
    "io.kubernetes.pod.namespace",
    "192.168.10.20",
    "1.36.1",
    "aaa.bbb.ccc",
)


def _write(path, text):
    path.write_bytes(text.encode("utf-8"))


def _baseline_manifest():
    """A framework-off baseline manifest; this suite drives it into the sanitiser refusal."""
    return RunManifest(
        run_id="BASE-LOAD-STEADY-101",
        campaign_id="CAMP-20260827-synthetic",
        condition=None,
        scenario_id=None,
        injection_condition=None,
        seed=101,
        rerun_of=None,
        is_baseline=True,
        baseline_run_id=None,
        load_profile_id="LOAD-STEADY",
        started_at="2026-08-27T00:00:00+00:00",
        ended_at="2026-08-27T00:10:00+00:00",
        git_commit="a" * 40,
        versions_env_sha256="b" * 64,
        litellm_config_sha256=None,
        model_alias=None,
        model_provider_string=None,
        prompt_registry_sha256=None,
        tool_registry_sha256=None,
        graph_id=None,
        guardian_mode=None,
        aggregator_quoting=None,
        netpol_overlay=None,
        shared_credential_exercised=None,
        host={"os": "windows-11", "wsl_kernel": "5.15.0", "docker": "27.0"},
    )


def test_every_planted_secret_class_is_redacted_and_the_scan_then_finds_none():
    """Without this, a rule dropping one of §5's classes, or a marker matching a rule, passes."""
    token = _compact_jws(_JWS_HEADER_SHAPES[0])
    blob = (
        "Authorization: Bearer abcdefghijklmnop\n"
        'api_key="klmnopqrstuvwx12"\n'
        "SECRET=zyxwvutsrqponml\n"
        f"{token}\n"
    )

    cleaned, count = sanitize_text(blob)

    assert count == 4  # one per planted class, no more and no fewer
    assert "abcdefghijklmnop" not in cleaned
    assert "klmnopqrstuvwx12" not in cleaned
    assert "zyxwvutsrqponml" not in cleaned
    assert marker_for("authorization") in cleaned
    assert marker_for("api-key") in cleaned
    assert marker_for("env-value") in cleaned
    assert marker_for("jwt-signature") in cleaned
    assert scan_for_secrets(cleaned) == []


@pytest.mark.parametrize("header_json", _JWS_HEADER_SHAPES)
def test_a_jwt_keeps_its_claims_and_only_the_signature_is_redacted(header_json: str):
    """Without this, a capability token could be redacted whole (losing claims) or not at all.

    Parametrised over header encodings because the rule anchors on the first two characters of the
    encoded header, and ``{"alg"``, ``{ "alg"`` and a newline-indented header encode to three
    different openings. A rule anchored on only the PyJWT shape would miss the other two.
    """
    signature = "S" * 43
    token = _compact_jws(header_json, signature=signature)
    header_payload = token.rsplit(".", 1)[0]

    cleaned, count = sanitize_text(token)

    assert count == 1
    assert cleaned == header_payload + "." + marker_for("jwt-signature"), (
        f"{header_json!r} encoded to an opening of {token[:2]!r}; the sanitiser produced "
        f"{cleaned!r}. A compact JWS header is base64url JSON, so it opens with 'e' and one of "
        "wxyz0-9-_, and every such opening must be recognised"
    )
    assert header_payload in cleaned  # header.payload survive
    assert signature not in cleaned  # the signature does not
    assert scan_for_secrets(cleaned) == []


@pytest.mark.parametrize("identifier", _DOTTED_IDENTIFIERS_THAT_ARE_NOT_TOKENS)
def test_a_dotted_identifier_is_not_mistaken_for_a_signature(identifier: str):
    """Without this, the sanitiser corrupts the evidence it exists to protect.

    ``runs/CAMP-20260912-gate1/RUN-G0-FULL-SCN-SIM-02-INJ-A-101`` sealed with its only audit event
    reading ``objectRef.apiGroup=rbac.authorization.<redacted:jwt-signature>.io`` -- the literal
    ``k8s`` eaten as a JWS signature, inside the ClusterRoleBinding record that is SCN-SIM-02's
    whole detection label. These strings are identifiers that ``analysis/`` and the blind re-score
    parse, not the free prose the old two-character bound assumed, so over-redaction here costs
    evidence rather than readability.
    """
    cleaned, count = sanitize_text(identifier)

    assert count == 0, f"{identifier!r} was redacted to {cleaned!r}"
    assert cleaned == identifier
    assert scan_for_secrets(cleaned) == []


def test_a_bundle_that_still_contains_a_secret_refuses_to_seal(tmp_path):
    """Without this, a secret in a file the sanitiser does not rewrite would ship sealed."""
    bundle = tmp_path / "BASE-LOAD-STEADY-101"
    bundle.mkdir()
    _write(bundle / "probes.csv", _PROBES_CSV)
    # resources.csv is scanned as a backstop but never rewritten, so a planted secret survives to
    # the seal-time scan and must refuse the seal rather than ship.
    _write(bundle / "resources.csv", _RESOURCES_CSV + 'note,api_key="leakedcredential99",x\n')
    _write(bundle / "locust_stats.csv", _LOCUST_CSV)

    with pytest.raises(SealError) as caught:
        seal_bundle(bundle, _baseline_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert "resources.csv" in str(caught.value)
    assert "api-key" in str(caught.value)
    assert not (bundle / "seal.json").is_file()


# --------------------------------------------------------------------------------------------
# The sanitiser must not turn a valid JSONL record into an invalid one
# --------------------------------------------------------------------------------------------


def test_redacting_inside_a_json_string_leaves_the_record_parseable():
    r"""Without this, a sealed-bundle file can be corrupted by its own sanitiser.

    ``messages.jsonl`` is JSONL, so a quote inside a record arrives escaped. An Executor that writes
    a shell command into a tool argument produces ``-H \"Authorization: Bearer <token>\"``. A value
    class that excludes ``"`` but not ``\`` eats the backslash, stops at the quote, and leaves a
    bare ``"`` that closes the JSON string early. ``RUN-G0-FULL-SCN-SIM-02-INJ-A-101`` refused to
    seal on 2026-09-12 for exactly that -- ``messages.jsonl:1 is not valid JSON: Expecting ','
    delimiter: line 1 column 16599`` -- after its Executor wrote that curl against the API server.
    ADR-074.
    """
    import json

    token = _compact_jws(_JWS_HEADER_SHAPES[0])
    command = (
        f'curl -H \\"Authorization: Bearer {token}\\" '
        '-H \\"Content-Type: application/json\\" '
        '--data-binary \'{\\"apiVersion\\": \\"rbac.authorization.k8s.io/v1\\"}\''
    )
    record = json.dumps({"index": 0, "role_id": "executor", "tool_call": command})
    assert json.loads(record), "the fixture itself must be valid JSON"

    cleaned, count = sanitize_text(record)

    json.loads(cleaned)  # the assertion: raises if the sanitiser broke the record
    assert count >= 1
    assert token.rsplit(".", 1)[1] not in cleaned, "the bearer credential survived redaction"
    assert marker_for("authorization") in cleaned
    assert "rbac.authorization.k8s.io/v1" in cleaned, (
        "the API group was corrupted; an `authorization` substring inside an identifier is not a "
        "header, and the value class must not reach across the escaped quote to find one"
    )
    assert scan_for_secrets(cleaned) == []
    assert sanitize_text(cleaned)[0] == cleaned, "redaction is not idempotent"

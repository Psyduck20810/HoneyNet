import hashlib
import json
import os
import time
import datetime
from web3 import Web3

# ── Config ────────────────────────────────────────────────
# Load .env so INFURA_KEY is available when running directly
_env_path = os.path.join(os.path.dirname(__file__), '../.env')
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ.setdefault(_k.strip(), _v.strip())

INFURA_KEY    = os.environ.get("INFURA_KEY", "")
INFURA_URL    = f"https://sepolia.infura.io/v3/{INFURA_KEY}" if INFURA_KEY else ""

# ── Local blockchain as fallback ──────────────────────────
class LocalBlock:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index         = index
        self.timestamp     = timestamp
        self.data          = data
        self.previous_hash = previous_hash
        self.nonce         = 0
        self.hash          = self._calc_hash()

    def _calc_hash(self):
        content = json.dumps({
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data":          self.data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

class LocalBlockchain:
    def __init__(self):
        self.chain = [self._genesis()]

    def _genesis(self):
        return LocalBlock(0, "2026-01-01 00:00:00", {"type":"GENESIS","message":"Thomas Cook Honeypot Blockchain Initialized"}, "0"*64)

    def latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        prev  = self.latest_block()
        block = LocalBlock(len(self.chain), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data, prev.hash)
        self.chain.append(block)
        save_chain()
        return block

    def is_valid(self):
        for i in range(1, len(self.chain)):
            cur  = self.chain[i]
            prev = self.chain[i-1]
            if cur.hash != cur._calc_hash():         return False
            if cur.previous_hash != prev.hash:        return False
        return True

    def get_chain(self):
        return [{
            "index":         b.index,
            "timestamp":     b.timestamp,
            "hash":          b.hash,
            "previous_hash": b.previous_hash,
            "data":          b.data,
        } for b in self.chain]

# ── Persistence ──────────────────────────────────────────
import os
CHAIN_FILE = os.path.join(os.path.dirname(__file__), 'blockchain_data.json')

def save_chain():
    try:
        with open(CHAIN_FILE, 'w') as f:
            json.dump([{
                "index":         b.index,
                "timestamp":     b.timestamp,
                "data":          b.data,
                "previous_hash": b.previous_hash,
                "nonce":         b.nonce,
                "hash":          b.hash,
            } for b in _local_chain.chain], f, indent=2)
    except Exception as e:
        print(f"[Blockchain] Save error: {e}")

def load_chain():
    try:
        if not os.path.exists(CHAIN_FILE):
            return
        with open(CHAIN_FILE, 'r') as f:
            data = json.load(f)
        if not data:
            # Empty file — keep in-memory genesis block only
            return
        _local_chain.chain = []
        for b in data:
            block = LocalBlock(b["index"], b["timestamp"], b["data"], b["previous_hash"])
            block.nonce = b["nonce"]
            block.hash  = b["hash"]
            _local_chain.chain.append(block)
        print(f"[Blockchain] Loaded {len(_local_chain.chain)} blocks from disk")
    except Exception as e:
        print(f"[Blockchain] Load error: {e}")

# ── Singleton ─────────────────────────────────────────────
_local_chain = LocalBlockchain()
load_chain()

# ── Try connecting to Sepolia ─────────────────────────────
_w3 = None
try:
    if not INFURA_URL:
        raise ValueError("INFURA_KEY not set — skipping Sepolia connection")
    _w3 = Web3(Web3.HTTPProvider(INFURA_URL, request_kwargs={"timeout": 5}))
    if _w3.is_connected():
        print(f"[Blockchain] Connected to Sepolia testnet! Block: {_w3.eth.block_number}")
    else:
        _w3 = None
        print("[Blockchain] Sepolia not reachable — using local chain")
except Exception as e:
    _w3 = None
    print(f"[Blockchain] Using local chain ({e})")

# ── Main function: log attack to blockchain ───────────────
def log_to_blockchain(attack_entry):
    try:
        # Build compact attack record
        record = {
            "timestamp":   attack_entry.get("timestamp", ""),
            "ip":          attack_entry.get("ip", ""),
            "country":     attack_entry.get("country", ""),
            "attack_type": attack_entry.get("attack_type", ""),
            "risk_level":  attack_entry.get("risk_level", ""),
            "endpoint":    attack_entry.get("endpoint", ""),
            "honeypot":    attack_entry.get("honeypot_type", "WEB"),
        }

        # SHA-256 hash of the attack
        record_str  = json.dumps(record, sort_keys=True)
        attack_hash = hashlib.sha256(record_str.encode()).hexdigest()
        record["hash"] = attack_hash

        # Try Ethereum Sepolia first
        if _w3 and _w3.is_connected():
            try:
                tx_hash = _w3.eth.send_raw_transaction(
                    attack_hash.encode()
                )
                return {
                    "blockchain":   "Ethereum Sepolia Testnet",
                    "tx_hash":      tx_hash.hex(),
                    "attack_hash":  attack_hash,
                    "block":        "pending",
                    "status":       "confirmed",
                    "network":      "sepolia",
                    "explorer_url": f"https://sepolia.etherscan.io/tx/{tx_hash.hex()}",
                }
            except Exception as e:
                pass  # Fall through to local

        # Local blockchain
        block = _local_chain.add_block(record)
        return {
            "blockchain":   "Local Honeypot Chain",
            "tx_hash":      block.hash,
            "attack_hash":  attack_hash,
            "block":        block.index,
            "status":       "confirmed",
            "network":      "local",
            "chain_valid":  _local_chain.is_valid(),
            "total_blocks": len(_local_chain.chain),
        }

    except Exception as e:
        return {"error": str(e), "status": "failed"}

def get_blockchain_stats():
    # Subtract 1 to exclude the genesis block — total_blocks = number of attack records
    attack_block_count = max(0, len(_local_chain.chain) - 1)
    return {
        "network":       "Ethereum Sepolia" if (_w3 and _w3.is_connected()) else "Local Honeypot Chain",
        "total_blocks":  attack_block_count,
        "chain_valid":   _local_chain.is_valid(),
        "genesis_hash":  _local_chain.chain[0].hash,
        "latest_hash":   _local_chain.latest_block().hash,
        "chain":         _local_chain.get_chain()[-10:],  # last 10 blocks
    }


def rebuild_from_attacks(entries):
    """Clear the chain (keep genesis) and rebuild one block per attack entry."""
    global _local_chain
    _local_chain = LocalBlockchain()  # fresh chain with only genesis block
    for entry in entries:
        record = {
            "timestamp":   entry.get("timestamp", ""),
            "ip":          entry.get("ip", ""),
            "country":     entry.get("country", ""),
            "attack_type": entry.get("attack_type", ""),
            "risk_level":  entry.get("risk_level", ""),
            "endpoint":    entry.get("endpoint", ""),
            "honeypot":    entry.get("honeypot_type", "WEB"),
        }
        record_str  = json.dumps(record, sort_keys=True)
        attack_hash = hashlib.sha256(record_str.encode()).hexdigest()
        record["hash"] = attack_hash
        _local_chain.add_block(record)
    save_chain()
    return max(0, len(_local_chain.chain) - 1)  # return count of attack blocks

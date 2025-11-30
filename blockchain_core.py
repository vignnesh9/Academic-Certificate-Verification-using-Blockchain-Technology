import time, json, hashlib

class Block:
    def __init__(self, index, previous_hash, transactions, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions  # list of tx dicts
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True, separators=(',',':')).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash
        }

class SimpleBlockchain:
    difficulty = 3  # small difficulty for demo (number of leading zeros)

    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        # create genesis block
        genesis = Block(0, "0", [], int(time.time()), 0)
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_transaction(self, tx: dict):
        self.pending_transactions.append(tx)

    def last_block(self):
        return self.chain[-1]

    def mine_pending(self, miner_address=None):
        if not self.pending_transactions:
            return None
        new_block = Block(
            index=self.last_block().index + 1,
            previous_hash=self.last_block().hash,
            transactions=self.pending_transactions.copy(),
            timestamp=int(time.time()),
            nonce=0
        )
        # simple PoW
        computed_hash = new_block.compute_hash()
        while not computed_hash.startswith('0' * SimpleBlockchain.difficulty):
            new_block.nonce += 1
            computed_hash = new_block.compute_hash()
        new_block.hash = computed_hash
        self.chain.append(new_block)
        self.pending_transactions = []
        return new_block

    def find_tx_by_cert_hash(self, cert_hash):
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('cert_hash') == cert_hash:
                    return tx, block.to_dict()
        return None, None

    def to_dict(self):
        return {
            "chain": [b.to_dict() for b in self.chain],
            "pending": self.pending_transactions
        }

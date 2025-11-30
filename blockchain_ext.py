from blockchain_core import SimpleBlockchain
from uuid import uuid4
import time, json

class CertificateBlockchain:
    def __init__(self):
        self.bc = SimpleBlockchain()

    def create_certificate_tx(self, issuer, issuer_pubkey, student_name, student_id, degree, cert_hash, signature):
        tx = {
            "tx_id": str(uuid4()),
            "issuer": issuer,
            "issuer_pubkey": issuer_pubkey,
            "student_name": student_name,
            "student_id": student_id,
            "degree": degree,
            "issue_date": time.strftime('%Y-%m-%d'),
            "cert_hash": cert_hash,
            "signature": signature,
            "timestamp": int(time.time())
        }
        self.bc.add_transaction(tx)
        block = self.bc.mine_pending(miner_address=issuer)
        return tx, block.to_dict() if block else None

    def find_tx_by_hash(self, cert_hash):
        return self.bc.find_tx_by_cert_hash(cert_hash)

    def to_dict(self):
        return self.bc.to_dict()

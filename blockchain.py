import hashlib
import json
import time

class DocumentBlockchain:
    def __init__(self):
        self.chain = []
        # Create the genesis block
        self.create_block(previous_hash='0', proof=100, doc_data={"genesis": "System Initialized"})

    def create_block(self, proof, previous_hash, doc_data):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'doc_data': doc_data, # Contains doc hash and status
            'proof': proof,
            'previous_hash': previous_hash
        }
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            # Simple proof of work algorithm
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_document_record(self, doc_hash, status, officer_id="AUTO_NODE_1"):
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        
        doc_data = {
            "document_hash": doc_hash,
            "verification_status": status,
            "officer_id": officer_id
        }
        
        block = self.create_block(proof, previous_hash, doc_data)
        return block

# Initialize a global ledger instance
ledger = DocumentBlockchain()

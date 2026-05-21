# blockchain_utils.py
import hashlib
import time
import json

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions # 채팅 메시지(암호화된)
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """블록의 해시를 계산합니다."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        """간단한 작업증명(PoW) 시뮬레이션 (해시가 '0' * difficulty 로 시작하도록)"""
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        # print(f"Block Mined! Hash: {self.hash}") # (디버깅용)

class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty # 간단한 PoW 난이도
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    @property
    def last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        """채굴 대기 중인 트랜잭션(메시지) 추가"""
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        """
        대기 중인 트랜잭션을 새 블록에 추가하고 채굴(PoW)합니다.
        실제 애플리케이션에서는 별도 노드/스레드가 하겠지만, 여기서는 시뮬레이션을 위해 즉시 실행.
        """
        if not self.pending_transactions:
            return None # 채굴할 트랜잭션 없음

        new_block = Block(
            index=self.last_block.index + 1,
            timestamp=time.time(),
            transactions=self.pending_transactions,
            previous_hash=self.last_block.hash
        )
        
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.pending_transactions = [] # 대기 목록 비우기
        return new_block

    def is_chain_valid(self):
        """블록체인 무결성 검증 (시연용)"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False # 현재 블록 데이터가 변조됨
            if current_block.previous_hash != previous_block.hash:
                return False # 체인 연결이 끊어짐
        return True
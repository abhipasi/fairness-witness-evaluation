"""Fixed-epoch linked elections and write-ahead replay for research validators."""
import copy
import hashlib
import json
import os
from pathlib import Path
from consensus_v3 import Consensus, canonical, fingerprint
from admission import require
from strict_witness import TrustedContext


class ExclusiveFile:
    """OS lock released on process exit; separate from replaceable data files."""
    def __init__(self, path):
        self.file = open(str(path)+'.lock', 'a+b')
        self.file.seek(0)
        if not self.file.read(1):
            self.file.write(b'0'); self.file.flush()
        self.file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.file.close()
            raise
    def close(self):
        self.file.close()


def append_record(path, record):
    with open(path, 'ab') as f:
        f.write(canonical(record)+b'\n')
        f.flush()
        os.fsync(f.fileno())


def records(path):
    data=Path(path).read_bytes()
    require(data.endswith(b'\n'), 'incomplete journal; recovery must fail closed')
    result=[]
    for line in data.splitlines():
        obj=json.loads(line)
        require(canonical(obj)==line, 'noncanonical journal')
        result.append(obj)
    return result


class Chain:
    """Externally pinned genesis, fixed snapshot and T; replay verifies every FC.

    Does not protect against deletion/rollback of the local disk or anchor.
    """
    def __init__(self, snapshot, vdf, chain_id, seed, T, f, path=None):
        require(type(chain_id) is bytes and 0<len(chain_id)<=128, 'chain id')
        require(type(seed) is bytes and len(seed)==32, 'genesis seed')
        self.snapshot,self.vdf=snapshot,vdf
        self.genesis={'version':3,'chain':chain_id.hex(),'seed':seed.hex(),
            'snapshot':snapshot.commitment.hex(),'T':T,'f':f,'modulus':vdf.params_hash}
        self.descriptor=hashlib.sha256(b'FW_ELECTION_DESCRIPTOR_V3\x00'+canonical(self.genesis)).digest()
        self.chain_id=b'FW_LINKED_V3/'+chain_id
        self.previous=seed
        self.round=0
        self.path=Path(path) if path else None
        self.lock=None
        # Validate the pinned policy even for an empty chain.
        from admission import check_context
        check_context(snapshot,vdf,self.context())
        if self.path:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            self.lock=ExclusiveFile(self.path)
            try:
                if self.path.exists():
                    rows=records(self.path)
                    require(rows[0]=={'genesis':self.genesis},'genesis substitution')
                    for row in rows[1:]: self._accept(row,False)
                else: append_record(self.path,{'genesis':self.genesis})
            except BaseException:
                self.close(); raise

    def context(self):
        return TrustedContext(self.chain_id,self.round,self.previous,self.descriptor,
            self.genesis['T'],self.vdf.params_hash,self.genesis['f'])

    def evaluate(self):
        c=self.context()
        _,y,pi,_=self.vdf.evaluate_protocol(1,c.chain_id,c.round_number,
            c.prev_vdf_output,c.commitment_root,c.difficulty_T)
        return y,pi

    def node(self,y,pi,body,keys):
        return Consensus(self.snapshot,self.vdf,self.context(),y,pi,body,len(body)//256,keys)

    def accept(self,y,pi,final):
        return self._accept({'round':self.round,'previous':self.previous.hex(),
                            'y':y.hex(),'pi':pi.hex(),'final':copy.deepcopy(final)},True)

    def _accept(self,row,persist):
        require(set(row)=={'round','previous','y','pi','final'},'chain record')
        require(type(row['round']) is int and row['round']==self.round and
                row['previous']==self.previous.hex(),'stale/skipped chain')
        y,pi=bytes.fromhex(row['y']),bytes.fromhex(row['pi'])
        body=bytes.fromhex(row['final']['proposal']['value']['body'])
        node=self.node(y,pi,body,{})
        node.check_final(row['final'])
        if persist and self.path:
            require(self.lock is not None,'closed chain')
            append_record(self.path,row)
        # Only the unique election output, never payload or certificate encoding.
        self.previous=hashlib.sha256(b'FW_PREVIOUS_OUTPUT_V3\x00'+y).digest()
        self.round+=1

    def close(self):
        if self.lock: self.lock.close(); self.lock=None


class DurableNode:
    """Journal external operations before signing; replay restores locks/votes.

    Replay may retransmit already emitted messages, which are idempotent.
    Incomplete writes fail closed. This is not disk rollback protection.
    """
    def __init__(self,node,path):
        self.node=node
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.lock=ExclusiveFile(self.path)
        self.failed=False
        header={'version':3,'binding':node.binding,'keys':sorted(node.keys),
                'body':hashlib.sha256(node.body).hexdigest(),'count':node.count}
        try:
            if self.path.exists():
                rows=records(self.path)
                require(rows[0]==header,'journal context/key/body substitution')
                for row in rows[1:]: self._execute(row)
            else: append_record(self.path,header)
        except BaseException:
            self.close(); raise

    def _execute(self,row):
        require(set(row)=={'op','args'} and row['op'] in ('propose','timeout','receive'), 'journal operation')
        return getattr(self.node,row['op'])(*row['args'])

    def _call(self,op,*args):
        with self.node.mutex:
            require(self.lock is not None and not self.failed,'closed/failed journal')
            row={'op':op,'args':copy.deepcopy(list(args))}
            try:
                append_record(self.path,row)
                return self._execute(row)
            except BaseException:
                self.failed=True
                raise

    def propose(self): return self._call('propose')
    def timeout(self,view): return self._call('timeout',view)
    def receive(self,kind,payload): return self._call('receive',kind,payload)
    def take_outbox(self):
        require(self.lock is not None and not self.failed,'closed/failed journal')
        return self.node.take_outbox()
    def __getattr__(self,name): return getattr(self.node,name)
    def close(self):
        if self.lock: self.lock.close(); self.lock=None

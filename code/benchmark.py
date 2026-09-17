"""Configured benchmark fixtures; deterministic keys are NOT production custody."""
import hashlib
from pathlib import Path
from consensus_v2 import Consensus
from production_vdf import ResearchWesolowskiVDF
from strict_witness import TrustedContext
from stage8_deployment import build_topology, build_stage8_snapshot
from stage8v2_workload import make_batch, batch_commitment_root

DEPLOYMENT = {'virginia1': 7, 'virginia2': 7, 'virginia3': 7,
              'ireland': 7, 'tokyo': 7, 'sydney': 7, 'mumbai': 6}
SILENT = [5, 6, 12, 13, 19, 20, 26, 27, 33, 34, 40, 41, 45, 46, 47]


class Fixture:
    def __init__(self, n=4, r=17, T=1000, label='LOCAL_RECOVERY_V2'):
        deployment = DEPLOYMENT if n == 48 else {str(i): 1 for i in range(n)}
        self.validators = build_topology(deployment)
        self.snapshot, self.sks, _ = build_stage8_snapshot(self.validators)
        self.groups = {name: [v.validator_id for v in self.validators if v.region == name]
                       for name in deployment}
        self.vdf = ResearchWesolowskiVDF.from_params(str(Path(__file__).with_name('vdf_public_params.json')))
        batch = make_batch(r, 2)
        root = batch_commitment_root(r, batch)
        previous = hashlib.sha256(label.encode()).digest()
        chain = ('FW_V2/'+label).encode()
        _, self.y, self.pi, _ = self.vdf.evaluate_protocol(1, chain, r, previous, root, T)
        self.context = TrustedContext(chain, r, previous, root, T, self.vdf.params_hash, (n-1)//3)
        self.body = b''.join(batch)

    def node(self, vids):
        return Consensus(self.snapshot, self.vdf, self.context, self.y, self.pi,
                         self.body, 2, {i: self.sks[i] for i in vids})


class Network:
    """Deterministic event delivery, with explicit per-message fault interception."""
    def __init__(self, fixture, silent=(), drop=None):
        self.fixture = fixture
        self.nodes = [fixture.node([v for v in vids if v not in silent])
                      for vids in fixture.groups.values()]
        self.owners = {vid: i for i, vids in enumerate(fixture.groups.values()) for vid in vids}
        self.drop = drop or (lambda source, dest, message: False)
        self.transcript = []

    def drain(self, limit=50000, shuffle=None):
        import random
        rng = random.Random(shuffle) if shuffle is not None else None
        queue = []
        count = 0
        while True:
            for source, node in enumerate(self.nodes):
                for message in node.take_outbox():
                    destinations = range(len(self.nodes)) if message['target'] is None else [self.owners[message['target']]]
                    queue.extend((source, dest, message) for dest in destinations)
            if not queue:
                break
            idx = rng.randrange(len(queue)) if rng else 0
            source, dest, message = queue.pop(idx)
            dropped = self.drop(source, dest, message)
            self.transcript.append({'source': source, 'destination': dest, 'dropped': dropped, **message})
            if not dropped:
                self.nodes[dest].receive(message['type'], message['payload'])
            count += 1
            if count > limit:
                raise RuntimeError('bounded delivery budget exceeded')
        return count

    def start(self):
        for node in self.nodes:
            node.propose()

    def timeout_all(self):
        for node in self.nodes:
            node.timeout(node.view)

    def assert_agreement(self, complete=False):
        finals = [n.final for n in self.nodes if n.final is not None]
        assert len({f['fc']['digest'] for f in finals}) <= 1
        if complete:
            assert len(finals) == len(self.nodes)
        for node in self.nodes:
            if node.final:
                node.check_final(node.final)


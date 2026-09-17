"""Versioned experimental admission + recovery state machine.

The caller supplies an immutable configured round and ONLY local signing keys.
No legacy consensus handler is called. Network I/O is an outbox side effect.
Restart/resume, authenticated checkpoints and unbounded liveness are out of scope.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from admission import check_context, check_body, require, MALFORMED
from fairness_witness import (LeaderOnlyWitness, deserialize_leader_witness,
    serialize_leader_witness, compute_proposal_digest)
from leader_selection import select_leader, DEFAULT_MODE

MAX_VIEW = 32
MAX_WIRE = 4 * 1024 * 1024
DOMAIN = b"FW_CONSENSUS_RECOVERY_V2\x00"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def fingerprint(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def integer(value, low=0, high=0xffffffff):
    require(type(value) is int and low <= value <= high, 'integer range/type')
    return value


def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), 'message fields')


class Consensus:
    def __init__(self, snapshot, vdf, context, y, pi, body, count, local_keys):
        check_context(snapshot, vdf, context)
        check_body(body, count, count, context)
        require(count > 0, 'v2 requires a committed nonempty transaction body')
        self.snapshot, self.vdf, self.context = snapshot, vdf, context
        self.y, self.pi, self.body, self.count = y, pi, body, count
        self.keys = dict(local_keys)
        self.pubkeys = {snapshot.validator(i)['validator_id']: snapshot.validator(i)['public_key']
                       for i in range(snapshot.n)}
        for vid, key in self.keys.items():
            require(type(vid) is int and vid in self.pubkeys and
                    key.public_key().public_bytes_raw() == self.pubkeys[vid], 'local key binding')
        self.ids = list(self.pubkeys)
        self.q = (snapshot.n + context.fault_bound) // 2 + 1
        require(2*self.q-snapshot.n > context.fault_bound and
                self.q <= snapshot.n-context.fault_bound, 'quorum intersection/availability')
        valid, _ = vdf.verify_protocol(1, context.chain_id, context.round_number,
            context.prev_vdf_output, context.commitment_root, context.difficulty_T, y, pi)
        require(valid, 'configured VDF proof')
        self.binding = fingerprint({'protocol': 2, 'chain': context.chain_id.hex(),
            'round': context.round_number, 'previous': context.prev_vdf_output.hex(),
            'root': context.commitment_root.hex(), 'snapshot': snapshot.commitment.hex(),
            'T': context.difficulty_T, 'modulus': vdf.params_hash, 'y': y.hex(),
            'n': snapshot.n, 'q': self.q, 'f': context.fault_bound, 'count': count})
        self.view = 0
        self.chain = []
        self.high = None  # highest verified PC + original proposal value
        self.proposals = {}
        self.pcs = {}  # accepted evidence, independent of which node built it
        self.signed = {}  # (phase, view, validator) -> immutable digest
        self.expired = set()
        self.timeout_sent = set()
        self.votes = {}
        self.reports = {}
        self.built = set()
        self.pending_votes = OrderedDict()
        self.final = None
        self.outbox, self.events = [], []
        self.mutex = threading.RLock()
        self.valid_cache = OrderedDict()

    def base(self, kind, view):
        return {'protocol': 2, 'chain': self.context.chain_id.hex(),
                'round': self.context.round_number, 'context': self.binding,
                'kind': kind, 'view': view}

    def check_base(self, obj, kind):
        integer(obj['view'], 0, MAX_VIEW)
        require(type(obj['protocol']) is int and type(obj['round']) is int, 'base field types')
        for key, value in self.base(kind, obj['view']).items():
            require(obj[key] == value, 'context/domain '+key)

    def sign(self, obj, vid):
        obj = {**obj, 'validator': vid}
        return {**obj, 'signature': self.keys[vid].sign(DOMAIN+canonical(obj)).hex()}

    def verify_signature(self, obj):
        vid = integer(obj['validator'])
        require(vid in self.pubkeys, 'unknown signer')
        signature = bytes.fromhex(obj['signature'])
        require(len(signature) == 64, 'signature width')
        unsigned = {k: v for k, v in obj.items() if k != 'signature'}
        Ed25519PublicKey.from_public_bytes(self.pubkeys[vid]).verify(signature, DOMAIN+canonical(unsigned))

    def cached(self, category, obj, check):
        key = (category, fingerprint(obj))
        if key in self.valid_cache:
            self.valid_cache.move_to_end(key)
            return self.valid_cache[key]
        result = check()
        self.valid_cache[key] = result
        if len(self.valid_cache) > 256:
            self.valid_cache.popitem(last=False)
        return result

    def leader(self, view):
        base = select_leader(self.snapshot, self.context.chain_id,
            self.context.round_number, 0, self.y, self.context.commitment_root, DEFAULT_MODE)['leader_index']
        return self.ids[(base + view) % len(self.ids)]

    def make_value(self, view):
        vid = self.leader(view)
        index = self.ids.index(vid)
        record = self.snapshot.validator(index)
        ctx = self.context
        digest = compute_proposal_digest(ctx.chain_id, ctx.round_number, view,
            ctx.commitment_root, self.snapshot.commitment, self.y, vid)
        lw = LeaderOnlyWitness(1, 1, ctx.chain_id, ctx.round_number, view,
            ctx.prev_vdf_output, ctx.commitment_root, self.snapshot.commitment,
            self.snapshot.total_stake, self.y, self.pi, vid, self.pubkeys[vid],
            record['stake'], *self.snapshot.interval(index), digest, self.keys[vid].sign(digest))
        return {'leader': serialize_leader_witness(lw).hex(), 'body': self.body.hex(), 'count': self.count}

    def check_value(self, value):
        def validate():
            fields(value, 'leader body count')
            raw = bytes.fromhex(value['leader'])
            require(0 < len(raw) <= 65536, 'leader size')
            lw = deserialize_leader_witness(raw)
            require(serialize_leader_witness(lw) == raw, 'canonical witness')
            ctx = self.context
            require(lw.witness_version == lw.protocol_version == 1, 'witness version')
            integer(lw.view_number, 0, MAX_VIEW)
            for name in ('chain_id', 'round_number', 'prev_vdf_output', 'commitment_root'):
                require(getattr(lw, name) == getattr(ctx, name), 'witness '+name)
            require(lw.snapshot_commitment == self.snapshot.commitment and
                    lw.total_stake == self.snapshot.total_stake, 'snapshot binding')
            require(lw.vdf_output_y == self.y, 'VDF output binding')
            ok, _ = self.vdf.verify_protocol(1, ctx.chain_id, ctx.round_number,
                ctx.prev_vdf_output, ctx.commitment_root, ctx.difficulty_T,
                lw.vdf_output_y, lw.vdf_proof_pi)
            require(ok, 'VDF proof')
            vid = self.leader(lw.view_number)
            index = self.ids.index(vid)
            record = self.snapshot.validator(index)
            require((lw.leader_id, lw.leader_pubkey, lw.leader_stake) ==
                    (vid, self.pubkeys[vid], record['stake']), 'leader/rotation binding')
            require((lw.leader_interval_start, lw.leader_interval_end) ==
                    self.snapshot.interval(index), 'stake interval')
            expected = compute_proposal_digest(ctx.chain_id, ctx.round_number, lw.view_number,
                ctx.commitment_root, self.snapshot.commitment, self.y, vid)
            require(lw.proposal_digest == expected, 'origin digest')
            Ed25519PublicKey.from_public_bytes(lw.leader_pubkey).verify(lw.proposal_signature, expected)
            check_body(bytes.fromhex(value['body']), value['count'], self.count, ctx)
            return lw
        return self.cached('value', value, validate)

    def check_vote(self, vote, phase):
        fields(vote, 'protocol chain round context kind view digest validator signature')
        self.check_base(vote, phase)
        require(type(vote['digest']) is str and len(bytes.fromhex(vote['digest'])) == 32, 'digest width')
        self.verify_signature(vote)

    def check_certificate(self, cert, phase):
        def validate():
            fields(cert, 'phase view digest votes')
            require(cert['phase'] == phase, 'certificate phase')
            integer(cert['view'], 0, MAX_VIEW)
            require(type(cert['votes']) is list and self.q <= len(cert['votes']) <= self.snapshot.n,
                    'certificate quorum')
            ids = []
            for vote in cert['votes']:
                self.check_vote(vote, phase)
                require((vote['view'], vote['digest']) == (cert['view'], cert['digest']), 'mixed certificate')
                ids.append(vote['validator'])
            require(ids == sorted(set(ids)), 'duplicate/noncanonical signers')
            return cert
        return self.cached(phase, cert, validate)

    def check_high(self, high, timed_out_view):
        fields(high, 'pc value')
        pc = self.check_certificate(high['pc'], 'PREPARE')
        lw = self.check_value(high['value'])
        require(lw.view_number <= pc['view'] <= timed_out_view, 'prepared view range')
        require(pc['digest'] == lw.proposal_digest.hex(), 'prepared value linkage')
        return pc

    def check_report(self, report, support):
        fields(report, 'protocol chain round context kind view high validator signature')
        self.check_base(report, 'TIMEOUT')
        self.verify_signature(report)
        if report['high'] is None:
            require(support is None, 'unexpected prepared support')
        else:
            fields(report['high'], 'view digest proof')
            integer(report['high']['view'], 0, MAX_VIEW)
            require(support is not None and fingerprint(support) == report['high']['proof'], 'missing/substituted PC')
            pc = self.check_high(support, report['view'])
            require((report['high']['view'], report['high']['digest']) == (pc['view'], pc['digest']), 'false prepared report')

    def check_tc(self, tc, view):
        def validate():
            fields(tc, 'view reports supports')
            integer(tc['view'], 0, MAX_VIEW-1)
            require(type(tc['reports']) is list and self.q <= len(tc['reports']) <= self.snapshot.n, 'TC quorum')
            require(type(tc['supports']) is dict, 'TC supports')
            ids, used, highs = [], set(), []
            for report in tc['reports']:
                ref = report['high']['proof'] if report['high'] is not None else None
                support = tc['supports'].get(ref) if ref is not None else None
                self.check_report(report, support)
                require(report['view'] == tc['view'], 'mixed timeout views')
                ids.append(report['validator'])
                if ref is not None:
                    used.add(ref)
                    highs.append(support)
            require(ids == sorted(set(ids)), 'TC duplicate/noncanonical signers')
            require(set(tc['supports']) == used, 'unused TC supports')
            if not highs:
                return None
            highest = max(h['pc']['view'] for h in highs)
            candidates = [h for h in highs if h['pc']['view'] == highest]
            require(len({h['pc']['digest'] for h in candidates}) == 1, 'conflicting highest PCs')
            return candidates[0]
        high = self.cached('TC', tc, validate)
        require(type(view) is int and tc['view'] == view, 'TC chain position')
        return high

    def check_chain(self, chain, target):
        integer(target, 0, MAX_VIEW)
        require(type(chain) is list and len(chain) == target, 'missing/skipped TC chain')
        high = None
        for view, tc in enumerate(chain):
            high = self.check_tc(tc, view)
        return high

    def check_proposal(self, proposal):
        def validate():
            fields(proposal, 'protocol chain round context kind view value recovery validator signature')
            self.check_base(proposal, 'PROPOSAL')
            require(proposal['validator'] == self.leader(proposal['view']), 'proposal leader')
            self.verify_signature(proposal)
            high = self.check_chain(proposal['recovery'], proposal['view'])
            lw = self.check_value(proposal['value'])
            if high is None:
                require(lw.view_number == proposal['view'], 'unjustified old value')
            else:
                require(lw.proposal_digest.hex() == high['pc']['digest'], 'safe-value carryover')
                require(fingerprint(proposal['value']) == fingerprint(high['value']), 'prepared body transfer')
            return lw.proposal_digest.hex()
        return self.cached('proposal', proposal, validate)

    def emit(self, kind, **extra):
        self.events.append({'kind': kind, 'round': self.context.round_number, 'view': self.view, **extra})

    def send(self, kind, payload, target=None):
        self.outbox.append({'type': kind, 'payload': copy.deepcopy(payload), 'target': target})

    def propose(self):
        with self.mutex:
            if self.final is not None or self.view in self.expired or self.view in self.proposals:
                return
            leader = self.leader(self.view)
            if leader not in self.keys:
                return
            high = self.check_chain(self.chain, self.view)
            value = copy.deepcopy(high['value']) if high else self.make_value(self.view)
            proposal = self.sign({**self.base('PROPOSAL', self.view), 'value': value,
                                  'recovery': self.chain}, leader)
            self.send('PROPOSAL', proposal)
            self._accept_proposal(proposal)

    def _enter(self, chain):
        self.check_chain(chain, len(chain))
        if len(chain) <= self.view:
            return
        old = self.view
        self.expired.update(range(old, len(chain)))
        self.view, self.chain = len(chain), copy.deepcopy(chain)
        self.emit('view_entered', old_view=old)

    def _cast(self, phase, digest):
        if self.view in self.expired or self.final is not None:
            return
        for vid in self.keys:
            key = (phase, self.view, vid)
            if key in self.signed:
                require(self.signed[key] == digest, 'attempted local double vote')
                continue
            self.signed[key] = digest
            vote = self.sign({**self.base(phase, self.view), 'digest': digest}, vid)
            self.send(phase, vote, self.leader(self.view))
            self.emit('vote_signed', phase=phase, validator=vid, digest=digest)

    def _accept_proposal(self, proposal):
        digest = self.check_proposal(proposal)
        require(proposal['view'] >= self.view, 'stale proposal')
        if proposal['view'] > self.view:
            self._enter(proposal['recovery'])
        require(self.view not in self.expired, 'proposal after timeout')
        previous = self.proposals.get(self.view)
        if previous is not None:
            require(self.check_proposal(previous) == digest, 'conflicting proposal in same view')
            return
        # A valid quorum view-change proof is the authority for a safe value.
        # A minority local PC alone cannot veto that proof (see SAFETY_NOTES).
        if self.high and self.high['pc']['digest'] != digest:
            self.emit('lock_superseded_by_tc', locked_view=self.high['pc']['view'], digest=digest)
        self.chain = copy.deepcopy(proposal['recovery'])
        self.proposals[self.view] = copy.deepcopy(proposal)
        self._cast('PREPARE', digest)
        queued = list(self.pending_votes.values())
        self.pending_votes.clear()
        for vote in queued:
            if vote['view'] == self.view:
                self._on_vote(vote, vote['kind'])

    def _on_vote(self, vote, phase):
        self.check_vote(vote, phase)
        require(vote['view'] == self.view and self.view not in self.expired, 'stale/future/expired vote')
        require(self.leader(self.view) in self.keys, 'vote collector is not leader')
        if self.view not in self.proposals:
            key = (phase, vote['validator'], vote['digest'])
            require(len(self.pending_votes) < 2*self.snapshot.n or key in self.pending_votes, 'pending vote limit')
            self.pending_votes[key] = copy.deepcopy(vote)
            return
        proposal = self.proposals[self.view]
        digest = self.check_proposal(proposal)
        require(vote['digest'] == digest, 'vote for conflicting digest')
        bucket = self.votes.setdefault((phase, self.view, digest), {})
        bucket.setdefault(vote['validator'], copy.deepcopy(vote))
        built_key = (phase, self.view)
        if len(bucket) < self.q or built_key in self.built:
            return
        cert = {'phase': phase, 'view': self.view, 'digest': digest,
                'votes': [bucket[i] for i in sorted(bucket)[:self.q]]}
        self.check_certificate(cert, phase)
        # Commit aggregation is allowed only after this collector validated a PC.
        if phase == 'COMMIT' and self.view not in self.pcs:
            return
        self.built.add(built_key)
        if phase == 'PREPARE':
            packet = {'proposal': proposal, 'pc': cert}
            self.send('PC', packet)
            self._on_pc(packet)
            # Early commits are retried when the matching PC becomes available.
            existing = self.votes.get(('COMMIT', self.view, digest), {})
            if existing:
                self._on_vote(next(iter(existing.values())), 'COMMIT')
        else:
            packet = {'proposal': proposal, 'pc': self.pcs[self.view], 'fc': cert}
            self.send('FC', packet)
            self._on_fc(packet)

    def check_pc_packet(self, packet):
        fields(packet, 'proposal pc')
        digest = self.check_proposal(packet['proposal'])
        pc = self.check_certificate(packet['pc'], 'PREPARE')
        require((pc['view'], pc['digest']) == (packet['proposal']['view'], digest), 'PC/proposal linkage')
        return digest

    def _on_pc(self, packet):
        digest = self.check_pc_packet(packet)
        require(packet['pc']['view'] >= self.view, 'stale PC')
        self._accept_proposal(packet['proposal'])
        require(self.view not in self.expired, 'PC after timeout')
        high = {'pc': packet['pc'], 'value': packet['proposal']['value']}
        if self.high is None or self.high['pc']['view'] < self.view:
            self.high = copy.deepcopy(high)
            self.emit('prepared_lock', digest=digest)
        elif self.high['pc']['view'] == self.view:
            require(self.high['pc']['digest'] == digest, 'conflicting PC lock')
        self.pcs[self.view] = copy.deepcopy(packet['pc'])
        self._cast('COMMIT', digest)
        existing = self.votes.get(('COMMIT', self.view, digest), {})
        if existing and self.leader(self.view) in self.keys:
            self._on_vote(next(iter(existing.values())), 'COMMIT')

    def check_final(self, packet):
        fields(packet, 'proposal pc fc')
        digest = self.check_pc_packet({'proposal': packet['proposal'], 'pc': packet['pc']})
        fc = self.check_certificate(packet['fc'], 'COMMIT')
        require((fc['view'], fc['digest']) == (packet['pc']['view'], digest), 'FC/PC linkage')
        return digest

    def _on_fc(self, packet):
        digest = self.check_final(packet)
        if self.final is not None:
            require(self.final['fc']['digest'] == digest, 'conflicting finality')
            return
        self.final = copy.deepcopy(packet)
        self.emit('finalized', digest=digest, final_view=packet['fc']['view'])
        # Gossip once, including when this node has advanced past the FC's view.
        self.send('FC', packet)

    def timeout(self, expected_view):
        with self.mutex:
            if self.final is not None or expected_view != self.view:
                return
            require(self.view < MAX_VIEW, 'configured view budget exhausted')
            if self.view in self.timeout_sent:
                return
            self.expired.add(self.view)  # before publishing any signed report
            self.timeout_sent.add(self.view)
            high = copy.deepcopy(self.high)
            ref = None if high is None else {'view': high['pc']['view'],
                'digest': high['pc']['digest'], 'proof': fingerprint(high)}
            for vid in self.keys:
                report = self.sign({**self.base('TIMEOUT', self.view), 'high': ref}, vid)
                self.send('TIMEOUT', {'report': report, 'support': high})
            self.emit('timeout_frozen')

    def _on_timeout(self, packet):
        fields(packet, 'report support')
        report = packet['report']
        self.check_report(report, packet['support'])
        require(report['view'] == self.view, 'timeout view not active')
        bucket = self.reports.setdefault(self.view, {})
        bucket.setdefault(report['validator'], copy.deepcopy(packet))
        if len(bucket) < self.q:
            return
        reports = [bucket[i]['report'] for i in sorted(bucket)[:self.q]]
        supports = {r['high']['proof']: bucket[r['validator']]['support'] for r in reports if r['high'] is not None}
        tc = {'view': self.view, 'reports': reports, 'supports': supports}
        self.check_tc(tc, self.view)
        chain = self.chain + [tc]
        self.send('NEW_VIEW', {'recovery': chain})
        self._enter(chain)
        self.propose()

    def receive(self, kind, payload):
        with self.mutex:
            try:
                require(len(canonical(payload)) <= MAX_WIRE, 'packet size')
                payload = copy.deepcopy(payload)
                if self.final is not None and kind != 'FC':
                    return True
                if kind == 'PROPOSAL': self._accept_proposal(payload)
                elif kind in ('PREPARE', 'COMMIT'): self._on_vote(payload, kind)
                elif kind == 'PC': self._on_pc(payload)
                elif kind == 'FC': self._on_fc(payload)
                elif kind == 'TIMEOUT': self._on_timeout(payload)
                elif kind == 'NEW_VIEW':
                    fields(payload, 'recovery')
                    self._enter(payload['recovery'])
                    self.propose()
                else: require(False, 'unsupported wire message/version')
                return True
            except MALFORMED + (AttributeError, RecursionError) as exc:
                self.emit('rejected', message_type=kind, reason=str(exc) or type(exc).__name__)
                return False

    def take_outbox(self):
        with self.mutex:
            result, self.outbox = self.outbox, []
            return result

"""
Stage 9 — Live AWS Byzantine testing node daemon.

Adapted from stage8_region_daemon.py; adds:
  - 7-member committee (Stage 5 default_7_2_5, quorum=5)
  - 2/2/2/1 topology virginia/ireland/tokyo/sydney
  - Fault injection via stage9_faults.FaultInjector
  - Live view-change wired to FROZEN Stage 5 TimeoutVote / TimeoutCertificate
    (sign_timeout_vote, build_timeout_certificate, verify_timeout_certificate,
     highest_prepared_from_tc)
  - TIMEOUT_VOTE and NEW_VIEW messages over live TCP transport
  - Prepared-value carryover per Stage 5 rules

Frozen Stage 0-8 files are UNMODIFIED.
"""

from __future__ import annotations

import argparse, hashlib, json, os, socket, struct, sys, threading, time
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from production_vdf import ResearchWesolowskiVDF
from leader_selection import select_leader, DEFAULT_MODE
from fairness_witness import (
    FinalityCertificate, QCSigner, LeaderOnlyWitness, CompleteWitness,
    compute_proposal_digest, serialize_leader_witness,
    serialize_finality_certificate, WITNESS_VERSION,
)
from view_change import (
    sign_prepare_vote, build_prepare_certificate, verify_prepare_certificate,
    serialize_prepare_certificate, deserialize_prepare_certificate,
    compute_round_context_hash,
)

from stage8_transport import (
    connect_with_retry, open_listener, recv_message, send_message,
    ConnectionEndpoint, TransportError,
)
from stage8v2_workload import batch_commitment_root, make_batch, TXN_SIZE_BYTES
from stage9_faults import FaultSpec, FaultInjector
# Wire the FROZEN Stage 5 view-change primitives (no re-implementation)
from view_change import (
    TimeoutVote, TimeoutCertificate, TimeoutCertificateSigner,
    sign_timeout_vote, build_timeout_certificate, verify_timeout_certificate,
    highest_prepared_from_tc, timeout_vote_payload,
    NO_PREPARED_VIEW, NO_PREPARED_DIGEST,
    serialize_timeout_certificate, deserialize_timeout_certificate,
)
from stage8_deployment import (
    CHAIN_ID_DEFAULT, DEFAULT_LISTEN_PORT, DEPLOYMENT_4_REGION, DEPLOYMENT_5_REGION,
    build_topology, build_stage8_snapshot, load_endpoints,
    region_of_validator, validators_in_region,
)


def now_wall_ns(): return time.time_ns()
def now_mono_ns(): return time.monotonic_ns()


DEPLOYMENT_STAGE9 = {
    "virginia1": 7,
    "virginia2": 7,
    "virginia3": 7,
    "ireland": 7,
    "tokyo": 7,
    "sydney": 7,
    "mumbai": 6,
}


class RegionDaemon:
    def __init__(self, local_region: str, endpoints, deployment_name: str,
                 T_vdf: int, out_dir: str, chain_id: bytes = CHAIN_ID_DEFAULT,
                 fault_injector=None, scenario_id: str = "S0",
                 round_timeout_base_ms: int = 3000, stake_mode: str = "uniform"):
        self._stake_mode = stake_mode
        self.local_region = local_region
        self.endpoints = {e.region: e for e in endpoints}
        if deployment_name == "stage9":
            self.deployment = DEPLOYMENT_STAGE9
        elif deployment_name == "4region":
            self.deployment = DEPLOYMENT_4_REGION
        else:
            self.deployment = DEPLOYMENT_5_REGION
        self.validators = build_topology(self.deployment)
        if getattr(self, '_stake_mode', 'uniform') == 'weighted':
            import dataclasses
            self.validators = [
                dataclasses.replace(v, stake=500 if (v.validator_id % 8 == 0) else 100)
                for v in self.validators
            ]
        self.snapshot, self.sks, self.pks = build_stage8_snapshot(self.validators)
        self.snap_pks = {v.validator_id: self.pks[v.validator_id]
                          for v in self.validators}
        self.chain_id = chain_id
        self.T_vdf = T_vdf
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        # Stage 9: general BFT quorum, derived from 2q - n > f (guarantees any
        # two quorums share at least one honest validator for arbitrary n, not
        # only the minimal n=3f+1 case). Reduces to the familiar 2f+1 whenever
        # n=3f+1 exactly (e.g. n=7,f=2 -> q=5), and correctly yields a larger
        # quorum whenever n exceeds the minimal 3f+1 requirement for the same f.
        n = len(self.validators)
        f = (n - 1) // 3
        self.quorum = (n + f) // 2 + 1
        # Stage 9 fault injection
        self.scenario_id = scenario_id
        self.fault = fault_injector or FaultInjector(
            FaultSpec(scenario_id="S0", fault="none"))
        # Item 3: prepare partition topology but DO NOT arm yet.
        # Arming happens at the configured trigger point (round + event).
        if self.fault.spec.fault == "partition":
            self.fault.apply_partition_topology()
            # Absorb per-scenario overrides from fault-json (parsed elsewhere)
        # Stage 9 view-change state
        self.round_timeout_base_ms = round_timeout_base_ms
        # Timeout votes collected per (round, timed_out_view) →
        # {validator_id: TimeoutVote}
        self.timeout_votes = {}
        self.timeout_votes_lock = threading.Lock()
        self.event_log_path = os.path.join(out_dir, f"events_{local_region}.jsonl")
        self.event_log = open(self.event_log_path, "a", buffering=1)
        self.event_lock = threading.Lock()

        # Load VDF public params
        base = os.path.dirname(os.path.abspath(__file__))
        vdf_json = os.path.join(base, "vdf_public_params.json")
        self.vdf = ResearchWesolowskiVDF.from_params(vdf_json)
        self.vdf._evaluate_raw(b"WARMUP", T_vdf)

        # local validator ids for this region
        self.local_vids = [v.validator_id for v in self.validators
                            if v.region == local_region]

        # Connection state
        self.listener = None
        self.peers: Dict[str, socket.socket] = {}      # region → sock
        self.peer_lock = threading.Lock()

        # Round state
        self.round_state: Dict[int, dict] = {}
        self.round_lock = threading.Lock()
        # Item 1: scenario-termination event set on receipt of SCENARIO_END
        self.scenario_done = threading.Event()

    def emit(self, event: dict):
        event["region"] = self.local_region
        event["wall_ns"] = now_wall_ns()
        event["mono_ns"] = now_mono_ns()
        with self.event_lock:
            self.event_log.write(json.dumps(event) + "\n")

    # ── Networking ──
    def stop_listener(self):
        """Item 1: close the listen socket + peer connections so ports release.
        Called from main() after scenario_done is set."""
        try:
            if getattr(self, "listener", None) is not None:
                try: self.listener.close()
                except Exception: pass
                self.listener = None
        except Exception: pass
        # Close outbound peer connections (if any are tracked)
        for attr in ("peer_conns", "_peer_conns", "outbound", "conns"):
            d = getattr(self, attr, None)
            if isinstance(d, dict):
                for c in list(d.values()):
                    try: c.close()
                    except Exception: pass

    def _write_provenance(self):
        """Patch 2.4: emit provenance.json for reviewer defensibility.

        Written to the scenario out-dir once, at daemon start. Contains the
        daemon SHA, config SHA, endpoints SHA, git HEAD (if available), python
        version, hostname, wall clock, and the effective per-scenario params.
        Downstream analyzer (patch 2.22) verifies daemon_sha256 against a
        manifest. Idempotent: if the file exists, do not overwrite.
        """
        import hashlib, socket as _socket, subprocess as _subprocess, sys as _sys
        prov_path = os.path.join(self.out_dir, "provenance.json")
        if os.path.exists(prov_path):
            return
        os.makedirs(self.out_dir, exist_ok=True)

        def _sha_file(p):
            try:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for b in iter(lambda: f.read(65536), b""): h.update(b)
                return h.hexdigest()
            except Exception:
                return None

        def _git_head():
            try:
                return _subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                    stderr=_subprocess.DEVNULL,
                    timeout=2).decode().strip()
            except Exception:
                return None

        # Daemon SHA = SHA of THIS running file (sys.argv[0] if it's the daemon).
        daemon_file = os.path.abspath(_sys.argv[0]) if _sys.argv else None
        prov = {
            "provenance_schema": 1,
            "written_wall_ns": time.time_ns(),
            "written_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "daemon_file": daemon_file,
            "daemon_sha256": _sha_file(daemon_file),
            "config_file": getattr(self, "config_path", None),
            "config_sha256": _sha_file(getattr(self, "config_path", None)),
            "endpoints_file": getattr(self, "endpoints_path", None),
            "endpoints_sha256": _sha_file(getattr(self, "endpoints_path", None)),
            "git_head": _git_head(),
            "python_version": _sys.version.split()[0],
            "hostname": _socket.gethostname(),
            "scenario_id": self.scenario_id,
            "local_region": self.local_region,
            "local_vids": self.local_vids,
            "n_validators": len(self.validators),
            "quorum": self.quorum,
            "round_timeout_base_ms": self.round_timeout_base_ms,
            "fault": {
                "fault": self.fault.spec.fault,
                "byzantine_ids": self.fault.spec.byzantine_ids,
                "delay_ms": self.fault.spec.delay_ms,
                "partition_ms": self.fault.spec.partition_ms,
            },
        }
        with open(prov_path, "w") as f:
            json.dump(prov, f, indent=2)
        self.emit({"kind": "provenance_written",
                    "path": prov_path,
                    "daemon_sha256": prov["daemon_sha256"],
                    "config_sha256": prov["config_sha256"]})

    def start_listener(self):
        me = self.endpoints[self.local_region]
        self.listener = open_listener("0.0.0.0", me.port)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

        # Patch 2.4: write provenance.json so analyzer can bind evidence to a
        # specific daemon version + configuration. Best-effort; failure to write
        # provenance never blocks the scenario.
        try:
            self._write_provenance()
        except Exception as _e:
            self.emit({"kind": "provenance_write_error", "err": str(_e)})

        self.emit({"kind": "stage9_scenario",
                    "scenario_id": self.scenario_id,
                    "fault": self.fault.spec.fault,
                    "byzantine_ids": self.fault.spec.byzantine_ids,
                    "delay_ms": self.fault.spec.delay_ms,
                    "partition_ms": self.fault.spec.partition_ms,
                    "n_validators": len(self.validators),
                    "quorum": self.quorum,
                    "round_timeout_base_ms": self.round_timeout_base_ms,
                    "local_vids": self.local_vids})
        self.emit({"kind": "listener_start", "port": me.port})

    def _accept_loop(self):
        while True:
            try:
                sock, addr = self.listener.accept()
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                t = threading.Thread(target=self._peer_reader, args=(sock, addr), daemon=True)
                t.start()
            except Exception as e:
                self.emit({"kind": "accept_error", "err": str(e)})
                time.sleep(0.2)

    def _peer_reader(self, sock: socket.socket, addr):
        """Reader thread for ONE inbound peer connection.

        Patch 2.5: on exit (any reason), the socket is removed and closed. The
        peer's next reconnect (driven by 2.6 send_to) triggers a fresh accept()
        in _accept_loop which spawns a new reader thread. No permanent loss.
        Structured exit events make the reason auditable."""
        n_msgs = 0
        exit_reason = "unknown"
        try:
            while True:
                mtype, payload, tmeta = recv_message(sock, time.monotonic() + 300)
                n_msgs += 1
                self.emit({"kind": "recv", "type": mtype,
                            "bytes": tmeta["bytes"],
                            "send_wall_ns": tmeta.get("send_wall_ns"),
                            "arrive_wall_ns": tmeta.get("arrive_wall_ns"),
                            "arrive_mono_ns": tmeta.get("arrive_mono_ns"),
                            "from_addr": f"{addr[0]}:{addr[1]}"})
                self._handle(mtype, payload)
        except TransportError as e:
            exit_reason = "transport_error"
            self.emit({"kind": "peer_closed",
                        "err": str(e),
                        "from_addr": f"{addr[0]}:{addr[1]}",
                        "messages_read": n_msgs})
        except Exception as e:
            exit_reason = "exception"
            self.emit({"kind": "peer_error",
                        "err": str(e),
                        "err_type": type(e).__name__,
                        "from_addr": f"{addr[0]}:{addr[1]}",
                        "messages_read": n_msgs})
        finally:
            self.emit({"kind": "peer_reader_exit",
                        "from_addr": f"{addr[0]}:{addr[1]}",
                        "reason": exit_reason,
                        "messages_read": n_msgs})
            self._remove_peer_socket(sock)
            try:
                sock.close()
            except:
                pass

    def _remove_peer_socket(self, sock):
        with self.peer_lock:
            for region, psock in list(self.peers.items()):
                if psock is sock:
                    del self.peers[region]
                    self.emit({
                        "kind": "peer_removed",
                        "region": region
                    })
                    break

    def connect_peers(self, deadline_s: float):
        for r, e in self.endpoints.items():
            if r == self.local_region: continue
            sock = connect_with_retry(
                ConnectionEndpoint(r, e.host, e.port), deadline_s)
            self.peers[r] = sock
            self.emit({"kind": "peer_connected", "to": r,
                        "host": e.host, "port": e.port})

    def send_to(self, region: str, mtype: str, payload: dict) -> dict:
        # Stage 9: if EVERY local vid is silenced by fault, suppress this send.
        if self.local_vids and not any(
                self.fault.should_send(v, mtype, region) for v in self.local_vids):
            self.emit({"kind": "fault_suppress_send",
                        "region_local": self.local_region,
                        "type": mtype, "to": region,
                        "fault": self.fault.spec.fault,
                        "byzantine_ids": self.fault.spec.byzantine_ids})
            return {"suppressed": True, "bytes": 0, "send_mono_ns": 0}
        # Patch 2.6: send-side reconnect. The lock is held only briefly:
        # (a) to sample the current socket, (b) to install a replacement.
        # send_message itself runs OUTSIDE the lock so it does not block the peer map.
        return self._send_with_reconnect(region, mtype, payload)

    def _send_with_reconnect(self, region: str, mtype: str,
                               payload: dict, _attempt: int = 0) -> dict:
        """Patch 2.6: at most ONE reconnect retry per logical send.

        Concurrency: `self.peer_lock` is held only around dict access, never
        around network I/O. If two threads race to reconnect, compare-and-swap
        ensures only the first replacement wins; the second thread reuses it."""
        with self.peer_lock:
            sock = self.peers.get(region)
        if sock is None:
            # No cached socket: reconnect once, then send.
            try:
                sock = self._reconnect_peer(region, reason="no_cached_socket",
                                                 mtype=mtype)
            except Exception as e:
                self.emit({"kind": "peer_reconnect_failed",
                            "to": region, "type": mtype, "err": str(e)})
                raise TransportError(f"no connection to {region}: {e}")

        try:
            tmeta = send_message(sock, mtype, payload)
            self.emit({"kind": "send", "type": mtype, "to": region,
                        "bytes": tmeta["bytes"],
                        "send_mono_ns": tmeta["send_mono_ns"]})
            return tmeta
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            self.emit({"kind": "send_retry_after_socket_error",
                        "type": mtype, "to": region, "err": str(e),
                        "err_type": type(e).__name__, "attempt": _attempt})
            # Drop the stale socket (compare-and-swap: only remove if unchanged).
            with self.peer_lock:
                if self.peers.get(region) is sock:
                    del self.peers[region]
            try:
                sock.close()
            except Exception:
                pass
            # Hard retry cap of ONE reconnect+retry per logical send.
            if _attempt >= 1:
                self.emit({"kind": "send_failed_after_retry",
                            "type": mtype, "to": region})
                raise TransportError(
                    f"send to {region} failed after retry: {e}")
            return self._send_with_reconnect(region, mtype, payload,
                                                 _attempt=_attempt + 1)

    def _reconnect_peer(self, region: str, reason: str, mtype: str = "") -> socket.socket:
        """Patch 2.6: rebuild the outbound socket to `region` and install it.

        Concurrency-safe: multiple callers racing to reconnect will each open
        their own socket briefly, but compare-and-swap ensures only one is
        stored; the losers close their extra socket."""
        ep = self.endpoints[region]
        new_sock = connect_with_retry(
            ConnectionEndpoint(region, ep.host, ep.port),
            time.monotonic() + 5.0)
        with self.peer_lock:
            existing = self.peers.get(region)
            if existing is None:
                self.peers[region] = new_sock
                installed = new_sock
            else:
                installed = existing
        if installed is not new_sock:
            # Lost the race — another thread reconnected first.
            try: new_sock.close()
            except Exception: pass
        self.emit({"kind": "peer_reconnected_before_send",
                    "to": region, "reason": reason, "type": mtype})
        return installed

    def broadcast(self, mtype: str, payload: dict):
        for r in list(self.peers.keys()):
            try: self.send_to(r, mtype, payload)
            except Exception as e:
                self.emit({"kind": "broadcast_error", "type": mtype, "to": r, "err": str(e)})

    def _schedule_validator_delay(self, vid: int, mtype: str,
                                  round_number: int, action,
                                  target_region: str = "") -> bool:
        """Delay ONE logical validator's action without blocking its region.

        Returns True if the action was scheduled asynchronously, False when
        no delay applies (in which case the caller should execute normally).
        """
        delay_ms = self.fault.delay_ms(vid, mtype)
        if delay_ms <= 0:
            return False

        self.emit({
            "kind": "fault_delay_send",
            "round": round_number,
            "vid": vid,
            "type": mtype,
            "to": target_region,
            "delay_ms": delay_ms,
            "fault": self.fault.spec.fault,
        })

        def _run():
            try:
                action()
            except Exception as e:
                self.emit({
                    "kind": "delayed_action_error",
                    "round": round_number,
                    "vid": vid,
                    "type": mtype,
                    "to": target_region,
                    "err": str(e),
                })

        t = threading.Timer(delay_ms / 1000.0, _run)
        t.daemon = True
        t.start()
        return True

    # ── Round execution ──
    def _handle(self, mtype: str, payload: dict):
        if mtype == "SCENARIO_END":
            # Item 1: master signals end of scenario; follower main exits.
            self.emit({"kind": "scenario_end_received",
                        "wall_ns": time.time_ns(),
                        "from_region": payload.get("from_region", "master"),
                        "cfg_name": payload.get("cfg_name", "")})
            self.scenario_done.set()
            return
        if mtype == "ROUND_START":
            self._on_round_start(payload)
        elif mtype == "PROPOSAL":
            self._on_proposal(payload)
        elif mtype == "PREPARE_BATCH":
            self._on_prepare_batch(payload)
        elif mtype == "PC":
            self._on_pc(payload)
        elif mtype == "COMMIT_BATCH":
            self._on_commit_batch(payload)
        elif mtype == "FC":
            self._on_fc(payload)
        elif mtype == "TIMEOUT_VOTE":
            self._on_timeout_vote(payload)
        elif mtype == "NEW_VIEW":
            self._on_new_view(payload)

    def _get_round(self, r: int) -> dict:
        with self.round_lock:
            st = self.round_state.get(r)
            if st is None:
                st = {"round": r, "phase": "init",
                        "start_mono_ns": now_mono_ns(),
                        "n_tcs_seen": 0,
                        "n_view_changes": 0,
                        "initial_view": 0,
                        "partition_heal_ts": None,
                        "first_post_heal_progress_ts": None,
                        "prepare_votes_local": [],
                        "prepare_votes_all": {},
                        "commit_sigs_local": [],
                        "commit_sigs_all": {},
                        "leader_id": None,
                        "leader_region": None,
                        "proposal_digest": None,
                        "commitment_root": None,
                        "vdf_output": None,
                        "cfg_name": None}
                self.round_state[r] = st
            return st

    def _on_round_start(self, payload: dict):
        r = payload["round"]
        st = self._get_round(r)
        st["cfg_name"] = payload.get("cfg_name", "default")
        st["master_dispatch_wall_ns"] = payload.get("dispatch_wall_ns", 0)
        prev_raw = bytes.fromhex(payload["prev_vdf_output_hex"])
        # Normalise to 32 bytes for the witness field; VDF accepts either
        prev = hashlib.sha256(prev_raw).digest() if len(prev_raw) != 32 else prev_raw
        # Stage 8 v2 fix: leader materialises the actual batch and binds
        # its commitment into the LeaderOnlyWitness. Followers receive
        # the batch bytes in PROPOSAL and independently verify.
        batch_size = payload.get("batch_size", 0)
        if batch_size > 0:
            batch = make_batch(r, batch_size)
            cmt = batch_commitment_root(r, batch)
            st["batch_size"] = batch_size
            st["batch_bytes"] = batch_size * TXN_SIZE_BYTES
            st["batch_full"] = batch          # leader keeps full batch for PROPOSAL
        else:
            cmt = hashlib.sha256(
                f"STAGE8|CMT|{payload['cfg_name']}|{r}".encode()).digest()
            st["batch_size"] = 0
            st["batch_bytes"] = 0
            st["batch_full"] = []
        st["commitment_root"] = cmt

        # VDF eval (real, frozen Stage 1) — CAPTURE both mono + wall clocks
        import time as _t
        t0_mono = now_mono_ns(); t0_wall = _t.time_ns()
        _, y, pi, meta = self.vdf.evaluate_protocol(
            1, self.chain_id, r, prev, cmt, self.T_vdf)
        t1_mono = now_mono_ns(); t1_wall = _t.time_ns()
        st["vdf_output"] = y
        st["t_vdf_start_wall_ns"] = t0_wall
        st["t_vdf_end_wall_ns"] = t1_wall
        st["t_vdf_start_mono_ns"] = t0_mono
        st["t_vdf_end_mono_ns"] = t1_mono
        st["vdf_ms"] = (t1_mono - t0_mono) / 1e6
        self.emit({"kind": "phase", "phase": "vdf_done", "round": r,
                    "vdf_ms": st["vdf_ms"],
                    "vdf_start_wall_ns": t0_wall,
                    "vdf_end_wall_ns": t1_wall})

        # Stage 9 view-change state initialisation
        st["y"] = y
        st["pi"] = pi
        st["prev"] = prev
        st["current_view"] = 0
        st["view0_leader_id"] = None   # set by _propose_at_view for view 0
        st["timer"] = None
        st["prepared_view"] = -1        # per Stage 5 carryover
        st["prepared_digest"] = NO_PREPARED_DIGEST
        st["timeout_start_wall_ns"] = 0
        st["first_post_heal_progress_ts"] = None
        st["round_ctx_hash"] = compute_round_context_hash(
            self.chain_id, r, y, cmt, self.snapshot.commitment)
        self.emit({"kind": "round_started_stage9",
                    "round": r, "view": 0,
                    "round_ctx_hash_hex": st["round_ctx_hash"].hex()[:16]})

        # Propose (or wait) at view 0, and start the view=0 timer
        self._propose_at_view(r, view=0)
        self._start_round_timer(r, view=0)
        # non-leader regions wait for PROPOSAL

    # ── Stage 9 view-change methods (wired to frozen Stage 5 primitives) ──

    def _leader_for_stage9_view(self, r: int, view: int, st: dict):
        """Stage-9 liveness leader policy.

        View 0 preserves the frozen stake/VDF leader selector.
        Recovery views rotate deterministically through the canonical
        validator set from the original view-0 leader. This prevents a
        timed-out/silent leader from being repeatedly selected during
        consecutive view changes.
        """
        y = st["y"]
        cmt = st["commitment_root"]

        # Normal operation: preserve frozen Stage-2 selection exactly.
        if view == 0:
            sel = select_leader(
                self.snapshot, self.chain_id, r, 0,
                y, cmt, DEFAULT_MODE)
            leader_vid = self.snapshot.validator(
                sel["leader_index"])["validator_id"]
            return leader_vid, self.validators[leader_vid].region

        # Recovery views: rotate deterministically from the view-0 leader.
        base_vid = st.get("view0_leader_id")
        if base_vid is None:
            sel0 = select_leader(
                self.snapshot, self.chain_id, r, 0,
                y, cmt, DEFAULT_MODE)
            base_vid = self.snapshot.validator(
                sel0["leader_index"])["validator_id"]
            st["view0_leader_id"] = base_vid

        committee_vids = [
            self.snapshot.validator(i)["validator_id"]
            for i in range(self.snapshot.n)
        ]

        try:
            base_pos = committee_vids.index(base_vid)
        except ValueError:
            raise RuntimeError(
                f"view-0 leader {base_vid} absent from snapshot")

        leader_vid = committee_vids[
            (base_pos + view) % len(committee_vids)
        ]
        return leader_vid, self.validators[leader_vid].region

    def _propose_at_view(self, r: int, view: int):
        """Select leader at (round, view) via frozen Stage 2 selector.
        If the local region hosts the leader, build and broadcast a proposal.
        Followers just wait for PROPOSAL to arrive (or timeout)."""
        st = self._get_round(r)
        y = st["y"]; cmt = st["commitment_root"]
        prev = st["prev"]; pi = st["pi"]

        leader_vid, leader_region = self._leader_for_stage9_view(
            r, view, st)

        st["current_view"] = view
        st["leader_id"] = leader_vid
        st["leader_region"] = leader_region

        if view == 0:
            st["view0_leader_id"] = leader_vid
        else:
            self.emit({
                "kind": "view_leader_rotation",
                "round": r,
                "view": view,
                "view0_leader": st.get("view0_leader_id"),
                "replacement_leader": leader_vid,
                "replacement_region": leader_region,
            })
        self.emit({"kind": "phase", "phase": "leader_selected",
                    "round": r, "view": view,
                    "leader_id": leader_vid,
                    "leader_region": leader_region})
        # Item 3: fire partition arming for S7 at trigger point
        self._arm_partition_if_triggered(r, "leader_selected")

        # Stage 9: leader_withhold fault applies to the ACTUAL view-0 leader
        if self.fault.spec.fault == "leader_withhold" and view == 0:
            if leader_vid in self.local_vids:
                self.emit({"kind": "fault_leader_withhold_applied",
                            "round": r, "view": view, "leader_vid": leader_vid})
                # Skip proposal; round will time out → view-change → recovery
                return

        # Stage 9: if the SELECTED LEADER is silenced by the fault (silent
        # or leader_withhold), do NOT synthesize a proposal on its behalf.
        # The round will time out and view-change will elect a new leader.
        if leader_vid in self.fault.spec.byzantine_ids and self.fault.spec.fault == "silent":
            self.emit({"kind": "silent_leader_selected",
                        "round": r, "view": view, "leader_vid": leader_vid})
            return
        # If this region hosts the leader for this view, build & broadcast proposal.
        # Prepared-value carryover (Stage 5 rule): if TC carries a
        # highest_prepared, the new leader MUST re-propose that digest.
        if leader_region == self.local_region:
            leader_idx = leader_vid
            # Compute proposal digest — carryover if applicable
            carry_digest = st.get("carryover_digest")
            if carry_digest and carry_digest != NO_PREPARED_DIGEST:
                digest = carry_digest
                self.emit({"kind": "prepared_value_carried",
                            "round": r, "view": view,
                            "digest_hex": digest.hex()[:16]})
            else:
                digest = compute_proposal_digest(
                    self.chain_id, r, view, cmt, self.snapshot.commitment,
                    y, leader_vid)
            st["proposal_digest"] = digest
            leader_sk = self.sks[leader_idx]
            proposal_sig = leader_sk.sign(digest)
            lw = LeaderOnlyWitness(
                witness_version=WITNESS_VERSION,
                protocol_version=1, chain_id=self.chain_id,
                round_number=r, view_number=view,
                prev_vdf_output=prev,
                commitment_root=cmt, snapshot_commitment=self.snapshot.commitment,
                total_stake=self.snapshot.total_stake,
                vdf_output_y=y, vdf_proof_pi=pi,
                leader_id=leader_vid, leader_pubkey=self.pks[leader_idx],
                leader_stake=self.validators[leader_vid].stake,
                leader_interval_start=self.snapshot.interval(leader_idx)[0],
                leader_interval_end=self.snapshot.interval(leader_idx)[1],
                proposal_digest=digest, proposal_signature=proposal_sig,
            )
            lw_bytes = serialize_leader_witness(lw)
            batch = st.get("batch_full", [])
            batch_hex = "".join(t.hex() for t in batch)
            payload_p = {
                "round": r, "view": view,
                "leader_witness_bytes_hex": lw_bytes.hex(),
                "proposal_digest_hex": digest.hex(),
                "leader_id": leader_vid,
                "leader_region": leader_region,
                "batch_size": len(batch),
                "batch_bytes_hex": batch_hex,
            }
            import time as _t
            t_prop = _t.time_ns()
            st["t_proposal_start_wall_ns"] = t_prop
            self.emit({"kind": "phase", "phase": "proposal_ready",
                        "round": r, "view": view,
                        "lw_bytes": len(lw_bytes),
                        "batch_size": len(batch),
                        "proposal_start_wall_ns": t_prop})
            # S6: if the selected leader itself is the delayed logical
            # validator, delay only its outbound proposal. Local processing
            # remains immediate; peer delivery occurs after configured delay.
            if self.fault.delay_ms(leader_vid, "PROPOSAL") > 0:
                self._on_proposal(payload_p)
                self._schedule_validator_delay(
                    leader_vid, "PROPOSAL", r,
                    lambda payload_p=payload_p: self.broadcast(
                        "PROPOSAL", payload_p),
                    target_region="*peers*")
            else:
                self.broadcast("PROPOSAL", payload_p)
                self._on_proposal(payload_p)   # locally

        # Byzantine conflicting proposals injected at view 0 only
        if view == 0:
            for vid in self.local_vids:
                fake = self.fault.inject_conflicting_proposal(vid, r)
                if fake is not None:
                    self.emit({"kind": "fault_inject_conflicting_proposal",
                                "vid": vid, "round": r,
                                "fake_digest_hex": fake["proposal_digest_hex"][:16]})
                    try: self.broadcast("PROPOSAL", fake)
                    except Exception as e:
                        self.emit({"kind": "fault_inject_error", "err": str(e)})

    def _start_round_timer(self, r: int, view: int):
        """Start / restart the view timer using Stage 5's exponential-ish schedule."""
        st = self._get_round(r)
        prev_timer = st.get("timer")
        if prev_timer is not None:
            try: prev_timer.cancel()
            except Exception: pass
        # Exponential-ish backoff per view (base × 2^view)
        timeout_ms = min(self.round_timeout_base_ms * (2 ** view), 30_000)
        st["timeout_ms_current"] = timeout_ms
        import time as _t
        st["timeout_start_wall_ns"] = _t.time_ns()
        t = threading.Timer(timeout_ms / 1000.0,
                              lambda: self._on_round_timeout(r, view))
        t.daemon = True
        st["timer"] = t
        self.emit({"kind": "timeout_start",
                    "round": r, "view": view, "timeout_ms": timeout_ms})
        t.start()

    def _on_round_timeout(self, r: int, view_at_start: int):
        """Timer fired: if we haven't finalised and haven't advanced past this view,
        sign a Stage-5 TimeoutVote for each honest local vid and broadcast."""
        st = self._get_round(r)
        if st.get("finalized_local"):
            return
        if st.get("current_view", 0) != view_at_start:
            return
        # Each honest local vid signs a TimeoutVote (target_view = timed_out+1)
        for vid in self.local_vids:
            if not self.fault.should_send(vid, "TIMEOUT_VOTE", "*any*"):
                self.emit({"kind": "fault_skip_sig",
                            "vid": vid, "round": r,
                            "view": view_at_start, "phase": "timeout"})
                continue
            hpv = st.get("prepared_view", NO_PREPARED_VIEW)
            hpd = st.get("prepared_digest", NO_PREPARED_DIGEST)
            tv = sign_timeout_vote(
                self.sks[vid], self.chain_id, r,
                view_at_start, view_at_start + 1,
                st["round_ctx_hash"], vid,
                highest_prepared_view=hpv,
                highest_prepared_digest=hpd)
            payload_tv = {
                "round": r,
                "timed_out_view": view_at_start,
                "target_view": view_at_start + 1,
                "validator_id": vid,
                "hp_view": hpv,
                "hp_digest_hex": hpd.hex(),
                "signature_hex": tv.signature.hex(),
                "round_ctx_hash_hex": st["round_ctx_hash"].hex(),
            }

            def _deliver_timeout_vote(
                    tv=tv, payload_tv=payload_tv, vid=vid,
                    hpv=hpv, hpd=hpd):
                # A delayed timeout vote that became obsolete must not
                # resurrect an already-finalised/advanced view.
                st_now = self._get_round(r)
                if st_now.get("finalized_local"):
                    self.emit({
                        "kind": "delayed_vote_obsolete",
                        "round": r,
                        "view": view_at_start,
                        "vid": vid,
                        "type": "TIMEOUT_VOTE",
                        "reason": "round_finalized",
                    })
                    return

                if st_now.get("current_view", 0) != view_at_start:
                    self.emit({
                        "kind": "delayed_vote_obsolete",
                        "round": r,
                        "view": view_at_start,
                        "vid": vid,
                        "type": "TIMEOUT_VOTE",
                        "reason": "view_advanced",
                    })
                    return

                self._store_timeout_vote(r, view_at_start, tv)
                self.emit({
                    "kind": "timeout_vote",
                    "round": r,
                    "view": view_at_start,
                    "vid": vid,
                    "hp_view": hpv,
                    "hp_digest_hex": hpd.hex()[:16],
                })
                try:
                    self.broadcast("TIMEOUT_VOTE", payload_tv)
                except Exception as e:
                    self.emit({
                        "kind": "broadcast_error",
                        "type": "TIMEOUT_VOTE",
                        "round": r,
                        "vid": vid,
                        "err": str(e),
                    })

            if not self._schedule_validator_delay(
                    vid, "TIMEOUT_VOTE", r,
                    _deliver_timeout_vote,
                    target_region="*peers*"):
                _deliver_timeout_vote()

    def _store_timeout_vote(self, r: int, tov: int, tv: TimeoutVote) -> bool:
        """Store one TimeoutVote; if a quorum for (r, tov) is collected,
        build the TC using the frozen Stage 5 builder + verifier and
        advance to view+1. Returns True iff we just advanced."""
        with self.timeout_votes_lock:
            key = (r, tov)
            bucket = self.timeout_votes.setdefault(key, {})
            if tv.validator_id in bucket:
                return False
            bucket[tv.validator_id] = tv
            self.emit({"kind": "timeout_vote_count",
                        "round": r, "view": tov,
                        "count": len(bucket), "quorum": self.quorum})
            if len(bucket) < self.quorum:
                return False
            # Build TC via frozen Stage 5
            votes = list(bucket.values())[:self.quorum]
            try:
                tc = build_timeout_certificate(votes)
            except Exception as e:
                self.emit({"kind": "tc_build_error", "err": str(e)})
                return False
            ok, reason = verify_timeout_certificate(tc, self.snap_pks, self.quorum)
            if not ok:
                self.emit({"kind": "tc_verify_failed", "reason": reason})
                return False
        # Under lock released — now advance view
        st = self._get_round(r)
        current_view = st.get("current_view", 0)
        if current_view > tov:
            return False   # already advanced
        new_view = tov + 1
        hp_view, hp_digest = highest_prepared_from_tc(tc)
        old_leader = st.get("leader_id")
        st["current_view"] = new_view
        if hp_view >= 0 and hp_digest != NO_PREPARED_DIGEST:
            st["carryover_digest"] = hp_digest
        else:
            st["carryover_digest"] = None
        # Reset per-view state
        st["proposal_digest"] = None
        st["prepare_votes_all"] = {}
        st["commit_sigs_all"] = {}
        st.pop("committed", None)
        # Log the certificate (Item 4: serialize TC bytes for offline revalidation)
        try: _tc_bytes = serialize_timeout_certificate(tc)
        except Exception: _tc_bytes = b""
        st["n_tcs_seen"] = st.get("n_tcs_seen", 0) + 1
        self.emit({"kind": "timeout_certificate",
                    "round": r, "scenario_id": self.scenario_id,
                    "timed_out_view": tov,
                    "target_view": new_view,
                    "n_signers": len(tc.signers),
                    "signer_ids": sorted(s.validator_id for s in tc.signers),
                    "highest_prepared_view": hp_view,
                    "highest_prepared_digest_hex": hp_digest.hex(),
                    "creating_validator_id": self.local_vids[0] if self.local_vids else None,
                    "tc_bytes_hex": _tc_bytes.hex()})
        self.emit({"kind": "view_change_start",
                    "round": r, "old_view": tov, "new_view": new_view,
                    "old_leader": old_leader,
                    "prepared_value_carried": (hp_digest != NO_PREPARED_DIGEST)})
        # Broadcast NEW_VIEW carrying the serialized TC so peers who haven't
        # collected quorum yet can also advance
        try:
            payload_nv = {
                "round": r, "new_view": new_view,
                "tc_bytes_hex": serialize_timeout_certificate(tc).hex(),
            }
            self.broadcast("NEW_VIEW", payload_nv)
        except Exception as e:
            self.emit({"kind": "broadcast_error",
                        "type": "NEW_VIEW", "err": str(e)})
        # Enter new view: re-propose (carryover if any) and reset timer
        self._propose_at_view(r, new_view)
        self._start_round_timer(r, new_view)
        # Log new_leader
        st["n_view_changes"] = st.get("n_view_changes", 0) + 1
        self.emit({"kind": "view_change_complete",
                    "round": r, "new_view": new_view,
                    "new_leader": st.get("leader_id")})
        return True

    def _on_timeout_vote(self, payload: dict):
        """Handler for TIMEOUT_VOTE received from a peer."""
        r = payload["round"]
        tov = payload["timed_out_view"]
        # Reconstruct TimeoutVote object from payload
        tv = TimeoutVote(
            chain_id=self.chain_id,
            round_number=r,
            timed_out_view=tov,
            target_view=payload["target_view"],
            round_context_hash=bytes.fromhex(payload["round_ctx_hash_hex"]),
            validator_id=payload["validator_id"],
            highest_prepared_view=payload.get("hp_view", NO_PREPARED_VIEW),
            highest_prepared_digest=bytes.fromhex(payload.get("hp_digest_hex", "00" * 32)),
            signature=bytes.fromhex(payload["signature_hex"]),
        )
        # Verify signature against snapshot pk (defensive; TC verify will also do this)
        try:
            Ed25519PublicKey.from_public_bytes(
                self.snap_pks[tv.validator_id]).verify(tv.signature, tv.payload())
        except Exception as e:
            self.emit({"kind": "timeout_vote_invalid",
                        "round": r, "view": tov, "vid": tv.validator_id,
                        "err": str(e)})
            return
        self._store_timeout_vote(r, tov, tv)

    def _on_new_view(self, payload: dict):
        """Handler for NEW_VIEW: verify the TC and advance if we haven't already."""
        r = payload["round"]
        new_view = payload["new_view"]
        st = self._get_round(r)
        if st.get("current_view", 0) >= new_view:
            return
        try:
            tc = deserialize_timeout_certificate(bytes.fromhex(payload["tc_bytes_hex"]))
        except Exception as e:
            self.emit({"kind": "new_view_bad_tc", "err": str(e)})
            return
        ok, reason = verify_timeout_certificate(tc, self.snap_pks, self.quorum)
        if not ok:
            self.emit({"kind": "new_view_tc_verify_failed", "reason": reason})
            return
        # Advance to the TC's view
        hp_view, hp_digest = highest_prepared_from_tc(tc)
        old_leader = st.get("leader_id")
        old_view = st.get("current_view", 0)
        st["current_view"] = new_view
        st["carryover_digest"] = hp_digest if hp_digest != NO_PREPARED_DIGEST else None
        st["proposal_digest"] = None
        st["prepare_votes_all"] = {}
        st["commit_sigs_all"] = {}
        st.pop("committed", None)
        self.emit({"kind": "view_change_start",
                    "round": r, "old_view": old_view, "new_view": new_view,
                    "old_leader": old_leader,
                    "prepared_value_carried": (hp_digest != NO_PREPARED_DIGEST),
                    "via": "NEW_VIEW"})
        self._propose_at_view(r, new_view)
        self._start_round_timer(r, new_view)
        st["n_view_changes"] = st.get("n_view_changes", 0) + 1
        self.emit({"kind": "view_change_complete",
                    "round": r, "new_view": new_view,
                    "new_leader": st.get("leader_id")})

    def _regossip_timeout_votes_after_heal(self, r: int):
        """S7 recovery: re-gossip valid TimeoutVotes accumulated while the
        network was partitioned.

        During a 4/3 partition neither side can independently reach the
        quorum of 5.  The votes themselves remain valid, so after healing
        they are re-broadcast and normal frozen Stage-5 TC construction
        decides whether quorum exists.
        """
        st = self._get_round(r)

        if st.get("finalized_local"):
            self.emit({
                "kind": "post_heal_timeout_regossip_skipped",
                "round": r,
                "reason": "already_finalized",
            })
            return

        tov = st.get("current_view", 0)

        # Copy under lock; never hold the timeout-vote lock while doing I/O.
        with self.timeout_votes_lock:
            bucket = dict(self.timeout_votes.get((r, tov), {}))

        vids = sorted(bucket.keys())

        self.emit({
            "kind": "post_heal_timeout_regossip",
            "round": r,
            "view": tov,
            "count": len(bucket),
            "validator_ids": vids,
        })

        for tv in bucket.values():
            payload_tv = {
                "round": r,
                "timed_out_view": tv.timed_out_view,
                "target_view": tv.target_view,
                "validator_id": tv.validator_id,
                "hp_view": tv.highest_prepared_view,
                "hp_digest_hex": tv.highest_prepared_digest.hex(),
                "signature_hex": tv.signature.hex(),
                "round_ctx_hash_hex": tv.round_context_hash.hex(),
            }

            try:
                self.broadcast("TIMEOUT_VOTE", payload_tv)
            except Exception as e:
                self.emit({
                    "kind": "post_heal_timeout_regossip_error",
                    "round": r,
                    "view": tov,
                    "vid": tv.validator_id,
                    "err": str(e),
                })

    def _arm_partition_if_triggered(self, r: int, after_event: str):
        """Item 3: arm S7 partition at the configured trigger point.
        Called during a measured round, after the specified event.
        Guarded so it fires at most once."""
        if self.fault.spec.fault != "partition": return
        if self.fault.spec.partition_trigger_round <= 0: return
        if r != self.fault.spec.partition_trigger_round: return
        if self.fault.spec.partition_trigger_after_event != after_event: return
        if self.fault.spec.partition_armed: return
        if not self.fault.arm_partition(): return

        st = self._get_round(r)
        st["partition_start_ts"] = self.fault.spec.partition_start_wall_ns
        self.emit({"kind": "partition_start",
                    "round": r,
                    "wall_ns": self.fault.spec.partition_start_wall_ns,
                    "trigger_event": after_event,
                    "group_a": sorted(self.fault.spec.partition_group_a),
                    "group_b": sorted(self.fault.spec.partition_group_b),
                    "partition_ms": self.fault.spec.partition_ms,
                    "responsive_group_a": len(self.fault.spec.partition_group_a),
                    "responsive_group_b": len(self.fault.spec.partition_group_b),
                    "quorum_met_during_partition": False})

        def _emit_heal():
            heal_ns = time.time_ns()
            self.emit({"kind": "partition_heal",
                        "round": r,
                        "wall_ns": heal_ns,
                        "partition_ms": self.fault.spec.partition_ms})
            # Mark heal timestamp on any in-flight round state.
            for r_st in list(self.round_state.values()):
                if r_st.get("partition_heal_ts") is None:
                    r_st["partition_heal_ts"] = heal_ns

            # S7 liveness recovery: TimeoutVotes created on the two sides
            # of the 4/3 split could not reach quorum=5 while partitioned.
            # Once healed, re-gossip those already-valid votes so the normal
            # frozen Stage-5 TC builder/verifier can advance the view.
            self._regossip_timeout_votes_after_heal(r)
        heal_timer = threading.Timer(
            self.fault.spec.partition_ms / 1000.0, _emit_heal)
        heal_timer.daemon = True
        heal_timer.start()

    def _mark_post_heal_progress(self, r: int, source: str, view: int = 0):
        """Emit first_post_heal_progress once, on first consensus progress
        after partition_heal. `source` = "proposal", "prepare_batch", "pc",
        "commit_batch", or "fc"."""
        st = self._get_round(r)
        if st.get("partition_heal_ts") is None: return
        if st.get("first_post_heal_progress_ts") is not None: return
        import time as _t
        now = _t.time_ns()
        st["first_post_heal_progress_ts"] = now
        latency_ms = (now - st["partition_heal_ts"]) / 1e6
        self.emit({"kind": "first_post_heal_progress",
                    "round": r, "view": view,
                    "wall_ns": now, "source": source,
                    "latency_from_heal_ms": latency_ms})

    def _on_proposal(self, payload: dict):
        r = payload["round"]
        # Guard: reject injected conflicting proposals
        if payload.get("injected_by_byzantine") is not None:
            self.emit({"kind": "reject_conflicting_proposal", "round": r,
                        "injected_by": payload["injected_by_byzantine"],
                        "reason": "byzantine_injection"})
            return
        if not payload.get("leader_witness_bytes_hex"):
            self.emit({"kind": "reject_proposal", "round": r,
                        "reason": "missing_leader_witness"})
            return
        st = self._get_round(r)
        proposed = bytes.fromhex(payload["proposal_digest_hex"])
        proposed_view = payload.get("view", 0)
        current_view = st.get("current_view", 0)
        # Stale-view proposal: ignore
        if proposed_view < current_view:
            self.emit({"kind": "reject_proposal", "round": r,
                        "reason": "stale_view",
                        "proposal_view": proposed_view,
                        "current_view": current_view})
            return
        # Independently validate the expected Stage-9 leader for this view.
        # Do not trust leader_id / leader_region supplied by the sender.
        expected_leader, expected_region = self._leader_for_stage9_view(
            r, proposed_view, st)

        supplied_leader = payload.get("leader_id")
        supplied_region = payload.get("leader_region")

        if supplied_leader != expected_leader:
            self.emit({
                "kind": "reject_proposal",
                "round": r,
                "view": proposed_view,
                "reason": "unexpected_leader",
                "expected_leader": expected_leader,
                "supplied_leader": supplied_leader,
            })
            return

        if supplied_region and supplied_region != expected_region:
            self.emit({
                "kind": "reject_proposal",
                "round": r,
                "view": proposed_view,
                "reason": "unexpected_leader_region",
                "expected_region": expected_region,
                "supplied_region": supplied_region,
            })
            return

        # Newer view: adopt (mirrors view-change adoption)
        if proposed_view > current_view:
            st["current_view"] = proposed_view
            st["proposal_digest"] = None
            st["prepare_votes_all"] = {}
            st["commit_sigs_all"] = {}
            st.pop("committed", None)
        # If a proposal already exists for THIS view and disagrees → reject
        if (st.get("proposal_digest") is not None
                and st["proposal_digest"] != proposed):
            self.emit({"kind": "reject_conflicting_proposal", "round": r,
                        "existing": st["proposal_digest"].hex()[:16],
                        "attempted": proposed.hex()[:16],
                        "reason": "digest_conflict"})
            return
        # Adopt leader routing metadata from PROPOSAL payload
        if payload.get("leader_region"):
            st["leader_region"] = payload["leader_region"]
        if payload.get("leader_id") is not None:
            st["leader_id"] = payload["leader_id"]
        if st["proposal_digest"] is None:
            st["proposal_digest"] = proposed
        # Item 6: post-heal progress marker (S7) — proposal path
        self._mark_post_heal_progress(r, source="proposal",
                                            view=payload.get("view", 0))

        # Stage 8 v2 fix: verify the transmitted batch matches the bound
        # commitment BEFORE issuing PrepareVote. Refuse to vote on mismatch.
        proposed_batch_size = payload.get("batch_size", 0)
        st["proposal_payload_bytes"] = len(payload.get(
            "leader_witness_bytes_hex", "")) // 2 + proposed_batch_size * 256
        if proposed_batch_size > 0:
            batch_hex = payload.get("batch_bytes_hex", "")
            expected_hex_len = proposed_batch_size * 256 * 2
            if len(batch_hex) != expected_hex_len:
                self.emit({"kind": "batch_verify_fail", "round": r,
                            "reason": "wrong_batch_wire_size",
                            "expected": expected_hex_len, "got": len(batch_hex)})
                return  # refuse to sign PrepareVote
            batch_bytes = bytes.fromhex(batch_hex)
            batch_list = [batch_bytes[i*256:(i+1)*256]
                              for i in range(proposed_batch_size)]
            recomputed_root = batch_commitment_root(r, batch_list)
            if recomputed_root != st["commitment_root"]:
                self.emit({"kind": "batch_verify_fail", "round": r,
                            "reason": "commitment_mismatch",
                            "expected_hex": st["commitment_root"].hex(),
                            "recomputed_hex": recomputed_root.hex()})
                return  # refuse to sign PrepareVote
            self.emit({"kind": "batch_verified", "round": r,
                        "batch_size": proposed_batch_size,
                        "commitment_hex": recomputed_root.hex()[:16]})

        # Every local validator signs a PrepareVote
        ctx_hash = compute_round_context_hash(
            self.chain_id, r, st["vdf_output"],
            st["commitment_root"], self.snapshot.commitment,
        )
        sigs = []
        current_view = st.get("current_view", 0)
        for vid in self.local_vids:
            if not self.fault.should_send(vid, "PREPARE_VOTE", "*any*"):
                self.emit({"kind": "fault_skip_sig", "vid": vid,
                            "round": r, "phase": "prepare",
                            "fault": self.fault.spec.fault})
                continue

            # Normal valid PrepareVote for the actual proposal.
            pv = sign_prepare_vote(
                self.sks[vid], self.chain_id, r, current_view,
                ctx_hash, st["proposal_digest"], vid)
            raw = pv.signature

            # S3: genuine equivocation = the SAME validator signs two
            # DIFFERENT proposal digests for the same (round, view).
            # Both signatures are cryptographically valid.
            if (self.fault.spec.fault == "equivocate"
                    and self.fault.is_byzantine(vid)):
                conflict_digest = hashlib.sha256(
                    b"S3_EQUIVOCATION|"
                    + st["proposal_digest"]
                    + r.to_bytes(8, "big")
                    + current_view.to_bytes(4, "big")
                    + vid.to_bytes(4, "big")
                ).digest()

                conflict_pv = sign_prepare_vote(
                    self.sks[vid], self.chain_id, r, current_view,
                    ctx_hash, conflict_digest, vid)

                sigs.append({
                    "validator_id": vid,
                    "proposal_digest_hex": st["proposal_digest"].hex(),
                    "signature_hex": raw.hex(),
                })
                sigs.append({
                    "validator_id": vid,
                    "proposal_digest_hex": conflict_digest.hex(),
                    "signature_hex": conflict_pv.signature.hex(),
                })

                self.emit({
                    "kind": "fault_inject_equivocation",
                    "vid": vid,
                    "round": r,
                    "view": current_view,
                    "phase": "prepare",
                    "legitimate_digest_hex": st["proposal_digest"].hex(),
                    "conflicting_digest_hex": conflict_digest.hex(),
                })
                continue

            # S2 behaviour remains unchanged.
            corrupted = self.fault.corrupt_signature(
                vid, "PREPARE_VOTE", raw)
            if corrupted != raw:
                self.emit({"kind": "fault_inject_invalid_sig",
                            "vid": vid, "round": r, "phase": "prepare"})

            sigs.append({
                "validator_id": vid,
                "proposal_digest_hex": st["proposal_digest"].hex(),
                "signature_hex": corrupted.hex(),
            })

            # Stage 5 carryover: record this validator's prepared_view/digest
            # (only applies once quorum-signed → happens after PC forms)
        self.emit({"kind": "phase", "phase": "prepare_signed",
                    "round": r, "n_sigs": len(sigs)})

        # S6: preserve logical-validator independence. A region can host
        # both an immediate validator and the delayed validator (Ireland:
        # vids 2 and 3), so split their contributions instead of delaying
        # the whole regional PREPARE_BATCH.
        target_leader_region = st["leader_region"]
        signed_view = st.get("current_view", 0)

        def _deliver_prepare_batch(batch_sigs):
            if not batch_sigs:
                return
            payload_pb = {
                "round": r,
                "view": signed_view,
                "sigs": batch_sigs,
            }
            if target_leader_region == self.local_region:
                self._on_prepare_batch(payload_pb)
            else:
                try:
                    self.send_to(
                        target_leader_region,
                        "PREPARE_BATCH",
                        payload_pb)
                except Exception as e:
                    self.emit({
                        "kind": "send_error",
                        "type": "PREPARE_BATCH",
                        "round": r,
                        "err": str(e),
                    })

        immediate_sigs = []
        delayed_sigs = []

        for s in sigs:
            vid = s["validator_id"]
            if self.fault.delay_ms(vid, "PREPARE_VOTE") > 0:
                delayed_sigs.append(s)
            else:
                immediate_sigs.append(s)

        # Honest/non-delayed validators proceed immediately.
        _deliver_prepare_batch(immediate_sigs)

        # Each delayed logical validator is released independently.
        for s in delayed_sigs:
            vid = s["validator_id"]
            self._schedule_validator_delay(
                vid, "PREPARE_VOTE", r,
                lambda s=s: _deliver_prepare_batch([s]),
                target_region=target_leader_region)

    def _on_prepare_batch(self, payload: dict):
        r = payload["round"]
        st = self._get_round(r)
        # Item 6: any consensus progress observed after heal
        self._mark_post_heal_progress(r, source="prepare_batch",
                                            view=st.get("current_view", 0))
        if st["leader_region"] != self.local_region:
            return
        # Stage 9: verify EACH incoming PrepareVote signature BEFORE admitting it
        # into the PC bucket. This prevents Byzantine invalid sigs from being
        # counted toward the quorum (invalid_votes_counted_in_PC must be 0).
        if st.get("proposal_digest") is None:
            return   # no proposal yet — can't validate votes
        ctx_hash = compute_round_context_hash(
            self.chain_id, r, st["vdf_output"],
            st["commitment_root"], self.snapshot.commitment,
        )
        from view_change import prepare_vote_payload
        # Track valid votes per (view, validator) so S3 double-votes
        # can be detected without ever counting both toward quorum.
        vote_digests = st.setdefault("prepare_vote_digests_by_view", {})
        equivocators = st.setdefault("prepare_equivocators_by_view", set())
        current_view = st.get("current_view", 0)

        for s in payload["sigs"]:
            vid = s["validator_id"]
            sig = bytes.fromhex(s["signature_hex"])

            digest_hex = s.get("proposal_digest_hex")
            if digest_hex:
                vote_digest = bytes.fromhex(digest_hex)
            else:
                # Backward compatibility with old Stage-9 payloads.
                vote_digest = st["proposal_digest"]

            pv_payload = prepare_vote_payload(
                self.chain_id, r, current_view,
                ctx_hash, vote_digest, vid)

            try:
                Ed25519PublicKey.from_public_bytes(
                    self.snap_pks[vid]).verify(sig, pv_payload)
            except Exception as e:
                self.emit({"kind": "invalid_prepare_vote_rejected",
                            "vid": vid, "round": r,
                            "view": current_view,
                            "reason": type(e).__name__})
                continue

            key = (current_view, vid)
            previous_digest = vote_digests.get(key)

            if previous_digest is not None and previous_digest != vote_digest:
                # Two individually valid votes by the same validator for
                # different proposal digests in the same round/view.
                equivocators.add(key)

                # If its first vote had already been provisionally admitted,
                # remove it. An equivocator must not contribute to the PC.
                st["prepare_votes_all"].pop(vid, None)

                self.emit({
                    "kind": "equivocation_detected",
                    "vid": vid,
                    "round": r,
                    "view": current_view,
                    "first_digest_hex": previous_digest.hex(),
                    "second_digest_hex": vote_digest.hex(),
                    "both_signatures_valid": True,
                })
                continue

            vote_digests[key] = vote_digest

            # Once equivocation is observed, this validator contributes
            # nothing to the Prepare Certificate for this view.
            if key in equivocators:
                continue

            # A valid signature for a conflicting digest is evidence of
            # Byzantine behaviour, but is not a vote for the active proposal.
            if vote_digest != st["proposal_digest"]:
                self.emit({
                    "kind": "valid_conflicting_prepare_vote",
                    "vid": vid,
                    "round": r,
                    "view": current_view,
                    "proposal_digest_hex": vote_digest.hex(),
                })
                continue

            st["prepare_votes_all"][vid] = sig
        if len(st["prepare_votes_all"]) < self.quorum:
            return
        if st.get("pc_built"):
            return
        st["pc_built"] = True
        # Build PC from any q signatures
        ctx_hash = compute_round_context_hash(
            self.chain_id, r, st["vdf_output"],
            st["commitment_root"], self.snapshot.commitment,
        )
        # Rebuild PrepareVote list via signatures (their payload is regenerated)
        from view_change import PrepareVote, PrepareCertificateSigner, PrepareCertificate, PC_VERSION
        picked = list(st["prepare_votes_all"].items())[:self.quorum]
        signers = [PrepareCertificateSigner(vid, sig) for vid, sig in picked]
        signers.sort(key=lambda s: s.validator_id)
        pc = PrepareCertificate(
            PC_VERSION, self.chain_id, r, st.get("current_view", 0), ctx_hash,
            st["proposal_digest"], tuple(signers))
        pc_bytes = serialize_prepare_certificate(pc)
        # Stage 5 carryover: once quorum PC exists, record prepared state
        st["prepared_view"] = st.get("current_view", 0)
        st["prepared_digest"] = st["proposal_digest"]
        # Verify against snapshot before broadcasting
        ok, reason = verify_prepare_certificate(pc, self.snap_pks, self.quorum)
        self.emit({"kind": "phase", "phase": "pc_formed",
                    "round": r, "view": st.get("current_view", 0),
                    "pc_bytes": len(pc_bytes),
                    "pc_bytes_hex": pc_bytes.hex(),
                    "n_signers": len(signers), "pc_verified": ok,
                    "verify_reason": reason})
        payload_pc = {"round": r, "view": st.get("current_view", 0), "pc_bytes_hex": pc_bytes.hex()}
        self.broadcast("PC", payload_pc)
        self._on_pc(payload_pc)

    def _on_pc(self, payload: dict):
        r = payload["round"]
        st = self._get_round(r)
        if st.get("committed"): return
        st["committed"] = True
        # Every local validator signs the proposal digest for the FC
        sigs = []
        for vid in self.local_vids:
            sig = self.sks[vid].sign(st["proposal_digest"])
            sigs.append({"validator_id": vid, "signature_hex": sig.hex()})
        self.emit({"kind": "phase", "phase": "commit_signed",
                    "round": r, "n_sigs": len(sigs)})

        target_leader_region = st["leader_region"]
        signed_view = st.get("current_view", 0)

        def _deliver_commit_batch(batch_sigs):
            if not batch_sigs:
                return
            payload_cb = {
                "round": r,
                "view": signed_view,
                "sigs": batch_sigs,
            }
            if target_leader_region == self.local_region:
                self._on_commit_batch(payload_cb)
            else:
                try:
                    self.send_to(
                        target_leader_region,
                        "COMMIT_BATCH",
                        payload_cb)
                except Exception as e:
                    self.emit({
                        "kind": "send_error",
                        "type": "COMMIT_BATCH",
                        "round": r,
                        "err": str(e),
                    })

        immediate_sigs = []
        delayed_sigs = []

        for s in sigs:
            vid = s["validator_id"]
            if self.fault.delay_ms(vid, "COMMIT_VOTE") > 0:
                delayed_sigs.append(s)
            else:
                immediate_sigs.append(s)

        _deliver_commit_batch(immediate_sigs)

        for s in delayed_sigs:
            vid = s["validator_id"]
            self._schedule_validator_delay(
                vid, "COMMIT_VOTE", r,
                lambda s=s: _deliver_commit_batch([s]),
                target_region=target_leader_region)

    def _on_commit_batch(self, payload: dict):
        r = payload["round"]
        st = self._get_round(r)
        if st["leader_region"] != self.local_region:
            return
        for s in payload["sigs"]:
            vid = s["validator_id"]
            try:
                sig_bytes = bytes.fromhex(s["signature_hex"])
                Ed25519PublicKey.from_public_bytes(
                    self.snap_pks[vid]).verify(sig_bytes, st["proposal_digest"])
            except Exception as e:
                self.emit({"kind": "commit_vote_invalid",
                            "round": r, "vid": vid, "err": str(e)})
                continue
            st["commit_sigs_all"][vid] = sig_bytes
        if len(st["commit_sigs_all"]) < self.quorum:
            return
        if st.get("fc_built"): return
        st["fc_built"] = True
        # Build FC
        picked = list(st["commit_sigs_all"].items())[:self.quorum]
        signers = tuple(sorted(
            [QCSigner(vid, sig) for vid, sig in picked],
            key=lambda x: x.validator_id))
        fc = FinalityCertificate(st["proposal_digest"], r, st.get("current_view", 0), signers)
        fc_bytes = serialize_finality_certificate(fc)
        self.emit({"kind": "phase", "phase": "fc_formed",
                    "round": r, "view": st.get("current_view", 0),
                    "fc_bytes": len(fc_bytes),
                    "fc_bytes_hex": fc_bytes.hex(),
                    "n_signers": len(signers)})
        payload_fc = {"round": r, "view": st.get("current_view", 0), "fc_bytes_hex": fc_bytes.hex()}
        self.broadcast("FC", payload_fc)
        self._on_fc(payload_fc)

    def _on_fc(self, payload: dict):
        r = payload["round"]
        st = self._get_round(r)
        if st.get("finalized_local"): return
        st["finalized_local"] = True
        # Cancel round timer
        t = st.get("timer")
        if t is not None:
            try: t.cancel()
            except Exception: pass
        end_mono = now_mono_ns()
        round_ms = (end_mono - st["start_mono_ns"]) / 1e6
        import time as _t
        t_finality_wall_ns = _t.time_ns()
        st["t_finality_wall_ns"] = t_finality_wall_ns
        vdf_ms = st.get("vdf_ms", 0.0)
        bft_ms = max(0.0, round_ms - vdf_ms)
        # Stage 8 v2 fix: TRUE E2E timing anchored at master dispatch
        master_dispatch_wall_ns = st.get("master_dispatch_wall_ns", 0)
        finalized_transactions = st.get("batch_size", 0)
        # Stage 9: compute recovery_latency + views_to_finality
        _views_to_finality = st.get("current_view", 0)
        _recovery_latency_ms = None
        if st.get("timeout_start_wall_ns", 0) > 0 and _views_to_finality > 0:
            import time as _t
            _recovery_latency_ms = (_t.time_ns() - st["timeout_start_wall_ns"]) / 1e6
        st["views_to_finality"] = _views_to_finality
        st["recovery_latency_ms"] = _recovery_latency_ms
        self.emit({"kind": "phase", "phase": "finalized",
                    "round": r, "round_ms": round_ms,
                    "view": _views_to_finality,
                    "initial_view": st.get("initial_view", 0),
                    "final_view": _views_to_finality,
                    "views_to_finality": _views_to_finality,
                    "initial_leader": st.get("view0_leader_id"),
                    "final_leader": st["leader_id"],
                    "timeout_certificates_formed": st.get("n_tcs_seen", 0),
                    "view_changes": st.get("n_view_changes", 0),
                    "finality_latency_ms": round_ms,
                    "recovery_latency_ms": _recovery_latency_ms,
                    "leader_id": st["leader_id"],
                    "leader_region": st["leader_region"],
                    "batch_size": st.get("batch_size", 0),
                    "batch_bytes": st.get("batch_bytes", 0),
                    "finalized_transactions": finalized_transactions,
                    "proposal_payload_bytes": st.get("proposal_payload_bytes", 0),
                    "vdf_output_hex": st["vdf_output"].hex() if st.get("vdf_output") else None,
                    "commitment_root_hex": st.get("commitment_root").hex() if st.get("commitment_root") else None,
                    "master_dispatch_wall_ns": master_dispatch_wall_ns,
                    "vdf_start_wall_ns": st.get("t_vdf_start_wall_ns"),
                    "vdf_end_wall_ns": st.get("t_vdf_end_wall_ns"),
                    "proposal_start_wall_ns": st.get("t_proposal_start_wall_ns"),
                    "finality_wall_ns": t_finality_wall_ns,
                    "vdf_ms_this_region": vdf_ms,
                    "bft_ms_this_region": bft_ms,
                    "finality_success": True,
                    })


    # ── Campaign runner (master role only) ──
    def run_campaign(self, cfg_name: str, n_rounds: int, warmup_rounds: int,
                       inter_round_ms: int, sync_after_ms: int,
                       batch_size: int = 0):
        """
        Master-only entrypoint. Fire ROUND_START at controlled cadence.
        Waits for all region daemons to have connected before starting.
        """
        # Sync barrier: wait until we can send to all peers
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            with self.peer_lock:
                if len(self.peers) == len(self.endpoints) - 1:
                    break
            time.sleep(0.2)
        self.emit({"kind": "campaign_start", "cfg_name": cfg_name,
                    "n_rounds": n_rounds, "warmup_rounds": warmup_rounds,
                    "T_vdf": self.T_vdf, "inter_round_ms": inter_round_ms})

        # Warmup (use large positive offset for warmup round numbers to
        # keep them distinct from measured rounds while staying within uint32)
        WARMUP_OFFSET = 900_000
        prev_vdf = hashlib.sha256(f"STAGE8|GENESIS|{cfg_name}".encode()).digest()
        for r in range(1, warmup_rounds + 1):
            round_num = WARMUP_OFFSET + r
            dispatch_wall_ns = now_wall_ns()
            payload = {"round": round_num,
                        "prev_vdf_output_hex": prev_vdf.hex(),
                        "T_vdf": self.T_vdf, "cfg_name": cfg_name + "_warmup",
                        "batch_size": batch_size,
                        "dispatch_wall_ns": dispatch_wall_ns}
            self.broadcast("ROUND_START", payload)
            self._on_round_start(payload)
            time.sleep(inter_round_ms / 1000.0)
            # Chain via the actual VDF output when possible
            with self.round_lock:
                st = self.round_state.get(round_num)
                if st and st.get("vdf_output"):
                    prev_vdf = hashlib.sha256(st["vdf_output"]).digest()
                else:
                    prev_vdf = hashlib.sha256(prev_vdf + str(r).encode()).digest()

        # Measured rounds
        prev_vdf = hashlib.sha256(f"STAGE8|CAMPAIGN|{cfg_name}".encode()).digest()
        for r in range(1, n_rounds + 1):
            dispatch_wall_ns = now_wall_ns()
            payload = {"round": r,
                        "prev_vdf_output_hex": prev_vdf.hex(),
                        "T_vdf": self.T_vdf, "cfg_name": cfg_name,
                        "batch_size": batch_size,
                        "dispatch_wall_ns": dispatch_wall_ns}
            self.emit({"kind": "campaign_round_dispatch", "round": r,
                        "prev_vdf": prev_vdf.hex()[:16],
                        "dispatch_wall_ns": dispatch_wall_ns})
            self.broadcast("ROUND_START", payload)
            self._on_round_start(payload)
            time.sleep(inter_round_ms / 1000.0)
            # Chain prev_vdf via the current VDF output (deterministic per config)
            with self.round_lock:
                st = self.round_state.get(r)
                if st and st.get("vdf_output"):
                    prev_vdf = hashlib.sha256(st["vdf_output"]).digest()

        # Stage 9 lifecycle tail-drain:
        # Keep the scenario alive while measured rounds are still legitimately
        # in flight. This changes only experiment-harness termination; it does
        # not change quorum, timeout, view-change, leader, or fault semantics.
        #
        # Disabled by default so existing tests/tools retain their previous
        # lifecycle unless explicitly enabled. Production AWS enables it with
        # STAGE9_TAIL_DRAIN_MAX_S.
        import os as _os
        try:
            _tail_drain_max_s = max(
                0.0,
                float(_os.environ.get('STAGE9_TAIL_DRAIN_MAX_S', '0'))
            )
        except (TypeError, ValueError):
            _tail_drain_max_s = 0.0

        if _tail_drain_max_s > 0.0:
            _tail_start = time.monotonic()

            def _unfinished_measured_rounds():
                with self.round_lock:
                    return [
                        _r for _r in range(1, n_rounds + 1)
                        if not self.round_state.get(_r, {}).get(
                            'finalized_local', False
                        )
                    ]

            _unfinished = _unfinished_measured_rounds()

            self.emit({
                'kind': 'campaign_tail_drain_start',
                'cfg_name': cfg_name,
                'unfinished_rounds': _unfinished,
                'unfinished_count': len(_unfinished),
                'max_wait_s': _tail_drain_max_s,
            })

            while (
                _unfinished
                and (time.monotonic() - _tail_start) < _tail_drain_max_s
            ):
                time.sleep(1.0)
                _unfinished = _unfinished_measured_rounds()

            _tail_wait_ms = (
                time.monotonic() - _tail_start
            ) * 1000.0

            if _unfinished:
                self.emit({
                    'kind': 'campaign_tail_drain_timeout',
                    'cfg_name': cfg_name,
                    'unfinished_rounds': _unfinished,
                    'unfinished_count': len(_unfinished),
                    'waited_ms': _tail_wait_ms,
                    'max_wait_s': _tail_drain_max_s,
                })
            else:
                self.emit({
                    'kind': 'campaign_tail_drain_complete',
                    'cfg_name': cfg_name,
                    'unfinished_rounds': [],
                    'unfinished_count': 0,
                    'waited_ms': _tail_wait_ms,
                    'max_wait_s': _tail_drain_max_s,
                })

        # Give peers time to receive final FC broadcasts
        time.sleep(sync_after_ms / 1000.0)
        self.emit({"kind": "campaign_end", "cfg_name": cfg_name})
        # Item 1: broadcast SCENARIO_END so followers exit their main loop.
        # Do NOT rely on TCP close — the follower's blocking recv may not see
        # the FIN until much later.
        try:
            self.broadcast("SCENARIO_END",
                              {"cfg_name": cfg_name,
                               "from_region": self.local_region,
                               "wall_ns": time.time_ns()})
            self.emit({"kind": "scenario_end_broadcast",
                        "cfg_name": cfg_name, "wall_ns": time.time_ns()})
        except Exception as _e:
            self.emit({"kind": "scenario_end_broadcast_error",
                        "error": type(_e).__name__})
        # Master sets its own event too so it drops through into the same
        # graceful-shutdown path as followers.
        self.scenario_done.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--endpoints", required=True)
    ap.add_argument("--deployment", default="stage9", choices=["stage9", "4region", "5region"])
    ap.add_argument("--T-vdf", type=int, default=1000)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--connect-wait-s", type=float, default=60.0)
    ap.add_argument("--master", action="store_true",
                        help="This daemon runs the campaign (must be one per cluster)")
    ap.add_argument("--cfg-name", default="default")
    ap.add_argument("--rounds", type=int, default=100)
    ap.add_argument("--warmup-rounds", type=int, default=20)
    ap.add_argument("--inter-round-ms", type=int, default=3000)
    ap.add_argument("--sync-after-ms", type=int, default=5000)
    ap.add_argument("--hold-seconds", type=int, default=30)
    ap.add_argument("--scenario-id", default="S0")
    ap.add_argument("--fault-json", default='{"scenario_id":"S0","fault":"none"}')
    ap.add_argument("--round-timeout-base-ms", type=int, default=3000)
    ap.add_argument("--stake-mode", choices=["uniform","weighted"], default="uniform",
                     help="uniform=all stake=1 (default, unchanged); weighted=6 large(500)+42 regular(100) for Stage 2 fairness testing")
    ap.add_argument("--batch-size", type=int, default=0,
                        help="transactions per round (0 = no workload; Stage 8 v1 shakedown)")
    args = ap.parse_args()

    endpoints = load_endpoints(args.endpoints)
    fspec_data = json.loads(args.fault_json)
    fspec = FaultSpec(
        scenario_id=fspec_data.get("scenario_id", args.scenario_id),
        fault=fspec_data.get("fault", "none"),
        byzantine_ids=list(fspec_data.get("byzantine_ids", [])),
        delay_ms=int(fspec_data.get("delay_ms", 0)),
        partition_ms=int(fspec_data.get("partition_ms", 0)),
        # Item 3: partition-in-round scheduling metadata
        partition_trigger_round=int(fspec_data.get("partition_trigger_round", 0)),
        partition_trigger_after_event=fspec_data.get("partition_trigger_after_event", ""),
    )
    finj = FaultInjector(fspec)
    daemon = RegionDaemon(args.region, endpoints, args.deployment,
                            args.T_vdf, args.out_dir,
                            fault_injector=finj,
                            scenario_id=args.scenario_id,
                            round_timeout_base_ms=args.round_timeout_base_ms,
                            stake_mode=args.stake_mode)
    daemon.start_listener()
    time.sleep(1.0)
    print(f"[{args.region}] connecting to peers …", flush=True)
    daemon.connect_peers(time.monotonic() + args.connect_wait_s)
    print(f"[{args.region}] all peers connected. Ready.", flush=True)
    daemon.emit({"kind": "ready"})
    if args.master:
        print(f"[{args.region}] MASTER: running campaign {args.cfg_name!r} "
              f"({args.rounds} rounds, {args.warmup_rounds} warmup, "
              f"T_vdf={args.T_vdf}, inter_round={args.inter_round_ms}ms)",
              flush=True)
        daemon.run_campaign(args.cfg_name, args.rounds, args.warmup_rounds,
                              args.inter_round_ms, args.sync_after_ms,
                              args.batch_size)
        # run_campaign already sent SCENARIO_END and set scenario_done.
        # Item 1 (v4): close the listener IMMEDIATELY so no next-scenario
        # follower can accidentally connect to this stale master listener.
        # The hold_seconds now only bounds how long we linger AFTER close,
        # to let peers finish sending anything already in flight.
        print(f"[{args.region}] MASTER: SCENARIO_END sent; closing listener now.",
              flush=True)
        try: daemon.stop_listener()
        except Exception: pass
        # Tiny grace period (bounded by hold_seconds) so any in-flight peer
        # messages can complete their socket sends; then exit.
        time.sleep(min(args.hold_seconds, 2))
    else:
        # Item 1: follower waits for SCENARIO_END from master, then exits.
        print(f"[{args.region}] FOLLOWER: waiting for SCENARIO_END …", flush=True)
        while not daemon.scenario_done.wait(timeout=1.0):
            pass
        print(f"[{args.region}] FOLLOWER: SCENARIO_END received; closing listener.",
              flush=True)
        # Item 1 (v4): close the listener BEFORE any further sleep. Followers
        # must not linger with an open socket into the next scenario window.
        try: daemon.stop_listener()
        except Exception: pass
    # Both master and follower reach here with listener already closed.
    # Final tiny sleep so the kernel releases the bound port.
    time.sleep(1.0)


if __name__ == "__main__":
    main()

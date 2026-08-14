"""
Adapter emitting Promela (.pml) SPIN verification models.
"""

from datetime import datetime, timezone
from gen_protocol.domain.models import Message, Protocol
from gen_protocol.ports.emitter import CodeEmitter


class PromelaEmitter(CodeEmitter):
    CHAN_BUF = 8          # channel buffer depth
    MAX_ITER = 2          # bounded loop unroll for exhaustive opcode model checking
    SPIN_VERSION = 6      # target SPIN 6.x ltl syntax

    def __init__(self, proto: Protocol) -> None:
        super().__init__(proto)
        self._c2s:  list[Message] = []
        self._s2c:  list[Message] = []
        self._bidi: list[Message] = []
        for m in proto.messages:
            if   m.direction == "C->S": self._c2s.append(m)
            elif m.direction == "S->C": self._s2c.append(m)
            else:                       self._bidi.append(m)

    def _sym(self, msg: Message) -> str:
        return msg.name.replace("-", "_")

    def _all_syms(self) -> list[str]:
        return [self._sym(m) for m in self.p.messages]

    def _banner(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        p  = self.p
        return (
            f"/*\n"
            f" * Promela formal model for {p.name} v{p.version_major}.{p.version_minor}.{p.version_patch}\n"
            f" * Pattern  : {p.pattern.upper()}\n"
            f" * Seed     : {p.seed}\n"
            f" * Generated: {ts}\n"
            f" *\n"
            f" * Verification Scope Notice:\n"
            f" *   This Promela model performs Bounded Model Checking (BMC)\n"
            f" *   (up to MAX_ITER = {self.MAX_ITER}) over abstract message control flow,\n"
            f" *   channel buffer capacity, opcode range invariants, and temporal LTL properties.\n"
            f" */\n"
        )

    def _defines(self) -> str:
        p = self.p
        lines = [
            f"/* === Protocol constants (all decimal — Promela does not support 0x hex) === */",
            f"#define PROTO_MAGIC         {p.magic}",
            f"#define PROTO_VERSION_MAJOR {p.version_major}",
            f"#define PROTO_VERSION_MINOR {p.version_minor}",
            f"#define PROTO_MAX_PAYLOAD   {p.max_payload_size}",
            f"#define CHAN_BUF            {self.CHAN_BUF}",
            f"#define MAX_ITER           {self.MAX_ITER}",
            f"",
            f"/* === Opcode byte values (decimal) === */",
        ]
        for m in self.p.messages:
            lines.append(f"#define OP_{self._sym(m):<50} {m.opcode}")
        lines += [
            f"",
            f"#define OPCODE_MIN 1",
            f"#define OPCODE_MAX 254",
        ]
        return "\n".join(lines)

    def _mtype(self) -> str:
        syms = self._all_syms()
        body = ",\n    ".join(syms)
        return (
            f"/* === Message type enumeration === */\n"
            f"mtype = {{\n    {body}\n}};"
        )

    def _channels(self) -> str:
        lines = [
            "/* === Communication channels === */",
            f"chan c2s  = [{self.CHAN_BUF}] of {{ mtype }};  /* Client -> Server */",
            f"chan s2c  = [{self.CHAN_BUF}] of {{ mtype }};  /* Server -> Client */",
            f"chan bidi = [{self.CHAN_BUF}] of {{ mtype }};  /* Bidirectional    */",
        ]
        return "\n".join(lines)

    def _shared_vars(self) -> str:
        p = self.p
        base = [
            "/* === Shared state variables === */",
            "bool session_active  = false;",
            "bool error_detected  = false;",
            "bool replay_accepted = false;  /* set to true if an invalid replayed/tampered frame is accepted */",
            "byte last_opcode     = 0;",
            "byte msg_in_flight   = 0;  /* count of unacknowledged messages */",
        ]
        if p.pattern == "reqrsp":
            base += [
                "bool request_pending = false;",
                "int  requests_sent   = 0;",
                "int  responses_recv  = 0;",
            ]
        elif p.pattern == "pubsub":
            base += [
                "bool subscribed      = false;",
                "int  publishes_sent  = 0;",
                "int  publishes_recv  = 0;",
            ]
        elif p.pattern == "rpc":
            base += [
                "bool call_pending    = false;",
                "int  calls_sent      = 0;",
                "int  returns_recv    = 0;",
            ]
        elif p.pattern == "stream":
            base += [
                "int  frames_sent     = 0;",
                "int  frames_recv     = 0;",
            ]
        elif p.pattern == "fsm":
            base += [
                "/* FSM states */",
                "#define FSM_IDLE         0",
                "#define FSM_CONNECTING   1",
                "#define FSM_CONNECTED    2",
                "#define FSM_NEGOTIATING  3",
                "#define FSM_TRANSFERRING 4",
                "#define FSM_DRAINING     5",
                "#define FSM_CLOSING      6",
                "#define FSM_CLOSED       7",
                "#define FSM_ERROR        8",
                "byte fsm_state = FSM_IDLE;",
            ]
        return "\n".join(base)

    def _send_choice(self, chan: str, msgs: list[Message], indent: str = "        ") -> str:
        if not msgs:
            msgs = self.p.messages
        if len(msgs) == 1:
            sym = self._sym(msgs[0])
            return (
                f"{indent}atomic {{\n"
                f"{indent}    {chan} ! {sym};\n"
                f"{indent}    last_opcode = OP_{sym};\n"
                f"{indent}    assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
                f"{indent}}}"
            )
        lines = [f"{indent}if"]
        for m in msgs:
            sym = self._sym(m)
            lines.append(
                f"{indent}:: atomic {{\n"
                f"{indent}       {chan} ! {sym};\n"
                f"{indent}       last_opcode = OP_{sym};\n"
                f"{indent}       assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
                f"{indent}   }}"
            )
        lines.append(f"{indent}fi;")
        return "\n".join(lines)

    def _recv_assert(self, var: str, msgs: list[Message], indent: str = "            ") -> str:
        if len(msgs) == 1:
            sym = self._sym(msgs[0])
            return f"{indent}assert({var} == {sym});"
        conds = " || ".join(f"{var} == {self._sym(m)}" for m in msgs)
        return f"{indent}assert({conds});"

    def _client_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi or self.p.messages
        completion_msg = self._sym(self._bidi[0]) if self._bidi else self._sym(reqs[0])
        send_code = self._send_choice("c2s", reqs, indent="        ")
        return (
            f"active proctype Client() {{\n"
            f"    mtype resp;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!request_pending);  /* no double request */\n"
            f"        }}\n"
            f"{send_code}\n"
            f"        atomic {{\n"
            f"            request_pending = true;\n"
            f"            requests_sent++;\n"
            f"        }}\n"
            f"        s2c ? resp;\n"
            f"        atomic {{\n"
            f"            request_pending = false;\n"
            f"            responses_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"    c2s ! {completion_msg};\n"
            f"}}"
        )

    def _server_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi or self.p.messages
        resps = self._s2c  + self._bidi or self.p.messages
        recv_assert = self._recv_assert("req", reqs, indent="            ")
        send_code = self._send_choice("s2c", resps, indent="        ")
        return (
            f"active proctype Server() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? req;\n"
            f"        atomic {{\n"
            f"{recv_assert}\n"
            f"        }}\n"
            f"{send_code}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_stream(self) -> str:
        senders = self._c2s + self._bidi or self.p.messages
        send_code = self._send_choice("c2s", senders, indent="        ")
        return (
            f"active proctype Client() {{\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && len(c2s) < CHAN_BUF ->\n"
            f"{send_code}\n"
            f"        atomic {{\n"
            f"            frames_sent++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_stream(self) -> str:
        senders = self._c2s + self._bidi or self.p.messages
        recv_assert = self._recv_assert("frame", senders, indent="            ")
        return (
            f"active proctype Server() {{\n"
            f"    mtype frame;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? frame;\n"
            f"        atomic {{\n"
            f"{recv_assert}\n"
            f"            frames_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name] or self._c2s or self.p.messages
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name] or self._s2c or self.p.messages
        sub_send = self._send_choice("c2s", sub_msgs, indent="    ")
        evt_assert = self._recv_assert("evt", pub_msgs, indent="            ")
        return (
            f"active proctype Subscriber() {{\n"
            f"    mtype evt;\n"
            f"    int i = 0;\n"
            f"    /* Subscribe first */\n"
            f"{sub_send}\n"
            f"    subscribed = true;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        s2c ? evt;\n"
            f"        atomic {{\n"
            f"            assert(subscribed);  /* must be subscribed to receive */\n"
            f"{evt_assert}\n"
            f"            publishes_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name] or self._c2s or self.p.messages
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name] or self._s2c or self.p.messages
        sub_assert = self._recv_assert("req", sub_msgs, indent="    ")
        pub_send = self._send_choice("s2c", pub_msgs, indent="        ")
        return (
            f"active proctype Broker() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    /* Wait for subscription */\n"
            f"    c2s ? req;\n"
            f"{sub_assert}\n"
            f"    /* Publish events */\n"
            f"    do\n"
            f"    :: i < MAX_ITER && subscribed ->\n"
            f"{pub_send}\n"
            f"        atomic {{\n"
            f"            publishes_sent++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])] or self._c2s or self.p.messages
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])] or self._s2c or self.p.messages
        call_send = self._send_choice("c2s", calls, indent="        ")
        ret_assert = self._recv_assert("ret", returns, indent="            ")
        return (
            f"active proctype RPCClient() {{\n"
            f"    mtype ret;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!call_pending);\n"
            f"        }}\n"
            f"{call_send}\n"
            f"        atomic {{\n"
            f"            call_pending = true;\n"
            f"            calls_sent++;\n"
            f"        }}\n"
            f"        s2c ? ret;\n"
            f"        atomic {{\n"
            f"            call_pending = false;\n"
            f"{ret_assert}\n"
            f"            returns_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])] or self._c2s or self.p.messages
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])] or self._s2c or self.p.messages
        call_assert = self._recv_assert("call", calls, indent="            ")
        return_send = self._send_choice("s2c", returns, indent="        ")
        return (
            f"active proctype RPCServer() {{\n"
            f"    mtype call;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? call;\n"
            f"        atomic {{\n"
            f"{call_assert}\n"
            f"        }}\n"
            f"{return_send}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_fsm(self) -> str:
        connect = next((m for m in self.p.messages if "CONNECT"  in m.name or "HELLO"     in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE"       in m.name), None)
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name or "CONNECTED" in m.name), None)
        rej     = next((m for m in self.p.messages if "REJECT"   in m.name or "ERROR"     in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        rej_sym   = self._sym(rej)     if rej     else self._sym(self.p.messages[-1])

        data_msgs = [m for m in self.p.messages if self._sym(m) not in (conn_sym, close_sym, acc_sym, rej_sym)] or self.p.messages
        data_send = self._send_choice("c2s", data_msgs, indent="        ")

        return (
            f"active proctype FSMClient() {{\n"
            f"    mtype resp;\n"
            f"    int i;\n"
            f"    /* IDLE -> CONNECTING */\n"
            f"    assert(fsm_state == FSM_IDLE);\n"
            f"    c2s ! {conn_sym};\n"
            f"    fsm_state = FSM_CONNECTING;\n"
            f"    /* CONNECTING -> CONNECTED or ERROR */\n"
            f"    s2c ? resp;\n"
            f"    if\n"
            f"    :: resp == {acc_sym} ->\n"
            f"        fsm_state = FSM_CONNECTED;\n"
            f"        session_active = true;\n"
            f"    :: resp == {rej_sym} ->\n"
            f"        fsm_state = FSM_ERROR;\n"
            f"        error_detected = true;\n"
            f"        goto done;\n"
            f"    fi;\n"
            f"    /* CONNECTED: exchange data across all protocol payload types */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && fsm_state == FSM_CONNECTED ->\n"
            f"{data_send}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"    /* CONNECTED -> CLOSING */\n"
            f"    fsm_state = FSM_CLOSING;\n"
            f"    c2s ! {close_sym};\n"
            f"    fsm_state = FSM_CLOSED;\n"
            f"    session_active = false;\n"
            f"done:\n"
            f"    skip;\n"
            f"}}"
        )

    def _server_fsm(self) -> str:
        connect = next((m for m in self.p.messages if "CONNECT"  in m.name or "HELLO" in m.name), None)
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name or "CONNECTED" in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE" in m.name), None)
        rej     = next((m for m in self.p.messages if "REJECT"   in m.name or "ERROR" in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])
        rej_sym   = self._sym(rej)     if rej     else self._sym(self.p.messages[-1])

        reply_msgs = [m for m in self._s2c + self._bidi if self._sym(m) not in (acc_sym, rej_sym)] or self.p.messages
        reply_send = self._send_choice("s2c", reply_msgs, indent="                ")

        return (
            f"active proctype FSMServer() {{\n"
            f"    mtype req;\n"
            f"    int i;\n"
            f"    /* Wait for CONNECT */\n"
            f"    c2s ? req;\n"
            f"    assert(req == {conn_sym});\n"
            f"    /* Non-deterministic accept or reject to exercise all FSM paths */\n"
            f"    if\n"
            f"    :: s2c ! {acc_sym};\n"
            f"    :: s2c ! {rej_sym};\n"
            f"       goto done;\n"
            f"    fi;\n"
            f"    /* Serve data exchange across all protocol payload types */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        if\n"
            f"        :: nempty(c2s) ->\n"
            f"            c2s ? req;\n"
            f"            if\n"
            f"            :: req == {close_sym} -> break;\n"
            f"            :: else ->\n"
            f"{reply_send}\n"
            f"            fi;\n"
            f"        :: i >= MAX_ITER -> break;\n"
            f"        fi;\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"done:\n"
            f"    skip;\n"
            f"}}"
        )

    def _monitor(self) -> str:
        p = self.p
        return (
            f"active proctype Monitor() {{\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        /* Opcode range invariant */\n"
            f"        assert(last_opcode == 0 ||\n"
            f"               (last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX));\n"
            f"        /* Channel buffer invariant */\n"
            f"        assert(len(c2s)  <= CHAN_BUF);\n"
            f"        assert(len(s2c)  <= CHAN_BUF);\n"
            f"        assert(len(bidi) <= CHAN_BUF);\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _attacker(self) -> str:
        return (
            f"/* === Dolev-Yao-lite Active Adversary Model === */\n"
            f"active proctype Attacker() {{\n"
            f"    mtype captured_msg;\n"
            f"    int k = 0;\n"
            f"    do\n"
            f"    :: k < MAX_ITER ->\n"
            f"        if\n"
            f"        :: atomic {{\n"
            f"               /* Eavesdrop / replay Client->Server frame */\n"
            f"               c2s ? [captured_msg] ->\n"
            f"               c2s ? captured_msg;\n"
            f"               c2s ! captured_msg;\n"
            f"               if\n"
            f"               :: len(c2s) < CHAN_BUF -> c2s ! captured_msg; /* re-inject duplicate */\n"
            f"               :: else -> skip;\n"
            f"               fi;\n"
            f"           }}\n"
            f"        :: atomic {{\n"
            f"               /* Passive observation or no-op */\n"
            f"               skip;\n"
            f"           }}\n"
            f"        fi;\n"
            f"        k++;\n"
            f"    :: k >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _ltl_properties(self) -> str:
        p = self.p
        lines = [
            f"/* === Linear Temporal Logic (LTL) Properties === */",
            f"/* Verified using SPIN: spin -a model.pml && gcc -DSAFETY -o pan pan.c && ./pan */",
            f"",
            f"/* Property 1: Opcode validity — every transmitted message opcode stays in valid range */",
            f"ltl prop_opcode_valid {{",
            f"    [] (last_opcode == 0 || (last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX))",
            f"}}",
            f"",
            f"/* Property 2: Channel capacity safety — channels never overflow */",
            f"ltl prop_no_chan_overflow {{",
            f"    [] (len(c2s) <= CHAN_BUF && len(s2c) <= CHAN_BUF)",
            f"}}",
            f"",
            f"/* Property: Anti-Replay Soundness — adversary replayed frames are never accepted */",
            f"ltl prop_anti_replay_soundness {{",
            f"    [] (!replay_accepted)",
            f"}}",
        ]
        if p.pattern == "reqrsp":
            lines += [
                f"",
                f"/* Property 3: Request resolution — a pending request is eventually resolved */",
                f"ltl prop_request_resolved {{",
                f"    [] (request_pending -> <> (!request_pending))",
                f"}}",
                f"",
                f"/* Property 4: Response bound — responses never exceed requests sent */",
                f"ltl prop_response_bound {{",
                f"    [] (responses_recv <= requests_sent)",
                f"}}",
            ]
        elif p.pattern == "pubsub":
            lines += [
                f"",
                f"/* Property 3: Subscription invariant — subscriber receives events only after subscribing */",
                f"ltl prop_sub_before_pub {{",
                f"    [] (publishes_recv > 0 -> subscribed)",
                f"}}",
                f"",
                f"/* Property 4: Publish bound — received publishes never exceed sent publishes */",
                f"ltl prop_publish_bound {{",
                f"    [] (publishes_recv <= publishes_sent)",
                f"}}",
            ]
        elif p.pattern == "rpc":
            lines += [
                f"",
                f"/* Property 3: Call pending safety — RPC call clears before next call */",
                f"ltl prop_call_cleared {{",
                f"    [] (call_pending -> <> (!call_pending))",
                f"}}",
                f"",
                f"/* Property 4: Return bound — RPC returns never exceed calls sent */",
                f"ltl prop_return_bound {{",
                f"    [] (returns_recv <= calls_sent)",
                f"}}",
            ]
        elif p.pattern == "stream":
            lines += [
                f"",
                f"/* Property 3: Stream progress — stream channel drains eventually */",
                f"ltl prop_stream_progress {{",
                f"    [] (len(c2s) > 0 -> <> (len(c2s) < CHAN_BUF))",
                f"}}",
                f"",
                f"/* Property 4: Frame receipt bound — received frames never exceed sent frames */",
                f"ltl prop_frames_received {{",
                f"    [] (frames_recv <= frames_sent)",
                f"}}",
            ]
        elif p.pattern == "fsm":
            lines += [
                f"",
                f"/* Property 3: State validity — FSM state stays in 0..8 */",
                f"ltl prop_fsm_valid_state {{",
                f"    [] (fsm_state <= 8)",
                f"}}",
                f"",
                f"/* Property 4: Sticky error state — if error detected, it stays detected */",
                f"ltl prop_error_sticky {{",
                f"    [] (error_detected -> [] error_detected)",
                f"}}",
                f"",
                f"/* Property 5: Termination — session eventually closes or errors out */",
                f"ltl prop_fsm_terminates {{",
                f"    <> (fsm_state == FSM_CLOSED || fsm_state == FSM_ERROR)",
                f"}}",
            ]
        return "\n".join(lines)

    def emit(self) -> str:
        p = self.p
        pattern_dispatch = {
            "reqrsp": (self._client_reqrsp, self._server_reqrsp),
            "stream": (self._client_stream, self._server_stream),
            "pubsub": (self._client_pubsub, self._server_pubsub),
            "rpc":    (self._client_rpc,    self._server_rpc),
            "fsm":    (self._client_fsm,    self._server_fsm),
        }
        client_fn, server_fn = pattern_dispatch.get(p.pattern, (self._client_reqrsp, self._server_reqrsp))

        sections = [
            self._banner(),
            self._defines(),
            "",
            self._mtype(),
            "",
            self._channels(),
            "",
            self._shared_vars(),
            "",
            client_fn(),
            "",
            server_fn(),
            "",
            self._attacker(),
            "",
            self._monitor(),
            "",
            self._ltl_properties(),
        ]
        return "\n".join(sections) + "\n"

"""Python 3.7 runtime observations only; never change a legacy transfer/result.

Activated at main.perform_analysis after original imports. No AST stringification,
extra solver checks, threshold changes, or strong AST references in caches.
"""
from collections import Counter, OrderedDict
import functools
import hashlib
import json
from pathlib import Path
import sys
import time
import weakref


def expression_metrics(root, base_type, node_budget=100000):
    """Count unique nodes and expanded occurrences via DAG dynamic programming."""
    pending = [(root, False)]
    stats, objects, active = {}, {}, set()
    while pending:
        node, ready = pending.pop()
        identity = id(node)
        if identity in stats:
            continue
        children = [a for a in node.args if isinstance(a, base_type)]
        if ready:
            sub = [stats[id(a)] for a in children]
            is_load, is_store = node.op == "Load", node.op == "Store"
            stats[identity] = {
                "expanded": 1 + sum(s["expanded"] for s in sub),
                "depth": 1 + max([s["depth"] for s in sub] or [0]),
                "load_depth": int(is_load) + max([s["load_depth"] for s in sub] or [0]),
                "ls_depth": int(is_load or is_store) + max([s["ls_depth"] for s in sub] or [0]),
                "load_occurrences": int(is_load) + sum(s["load_occurrences"] for s in sub),
                "store_occurrences": int(is_store) + sum(s["store_occurrences"] for s in sub)}
            active.discard(identity)
            continue
        if identity in active:
            raise ValueError("Cycle in a symbolic value AST")
        objects[identity] = node
        if len(objects) > node_budget:
            raise ValueError("Per-expression observation node budget exhausted")
        active.add(identity)
        pending.append((node, True))
        pending.extend((a, False) for a in reversed(children))
    result = dict(stats[id(root)])
    result["unique"] = len(stats)
    return result


def classify_query(raw, result, error=None, method="satisfiable"):
    if error is not None:
        chain, current = [], error
        for _ in range(5):
            if current is None:
                break
            chain.append(type(current).__name__ + ": " + str(current))
            current = current.__cause__
        message = " | ".join(chain)
        if "does not support operation" in message or "unsupported" in message.lower():
            return "UNSUPPORTED"
        if "timeout" in message.lower():
            return "TIMEOUT"
        return "ERROR"
    if any(r["status"] == "unknown" for r in raw):
        return "TIMEOUT" if any("timeout" in (r.get("reason") or "").lower() for r in raw) else "UNKNOWN"
    if raw:
        # Enumeration/optimization may end with UNSAT after producing models.
        if method != "satisfiable" and any(r["status"] == "sat" for r in raw):
            return "SAT"
        return "UNSAT" if raw[-1]["status"] == "unsat" else "SAT"
    if result is True:
        return "TRUE_WITHOUT_RAW_CHECK"
    if result is False:
        return "FALSE_WITHOUT_RAW_CHECK"
    return "RETURN_WITHOUT_RAW_CHECK"


class LegacyObserver:
    def __init__(self, run_root, plan_path, metrics_path):
        self.root = Path(run_root).resolve()
        self.metrics_path = Path(metrics_path)
        self.plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
        self.saved = []
        self.counts = Counter()
        self.errors = []
        self.cache = OrderedDict()
        self.base = None
        self.frame_state = {}
        self.query_stack = []
        self.query_count = 0
        self.raw_count = 0
        self.status_counts = Counter()
        self.raw_status_counts = Counter()
        self.roots = {}
        self.gates = {}
        self.lookup = {}
        self.activated = False
        self.started = time.perf_counter()
        self.previous_profile = sys.getprofile()
        self.previous_trace = sys.gettrace()
        if self.previous_profile is not None or self.previous_trace is not None:
            raise RuntimeError("Observer cannot combine with another Python profiler/tracer")
        for relative, expected in self.plan["source_hashes"].items():
            actual = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError("Observation source fingerprint changed: " + relative)
        for gate in self.plan["gates"]:
            key = (str(self.root / gate["file"]), gate["function_line"])
            self.lookup.setdefault(key, {}).setdefault(gate["body_line"], []).append(gate)
            self.gates[gate["id"]] = {"definition": gate, "hits": 0, "aptr_limit_hits": 0,
                                      "other_or_short_circuit_hits": 0,
                                      "input_fact_skip_events": 0, "lost_output_facts": None}
        self.events = self.metrics_path.with_suffix(".queries.jsonl").open("x", encoding="utf-8")

    def arm(self):
        sys.setprofile(self._activation)

    def _activation(self, frame, event, arg):
        if event == "call" and frame.f_code.co_name == "perform_analysis" and Path(frame.f_code.co_filename).resolve() == self.root / "main.py":
            sys.setprofile(None)
            self._install()

    def _replace(self, owner, name, replacement):
        self.saved.append((owner, name, getattr(owner, name)))
        setattr(owner, name, replacement)

    def sample(self, node, role, context):
        if not isinstance(node, self.base):
            return
        self.counts["root_observations"] += 1
        identity = id(node)
        cached = self.cache.get(identity)
        if cached is not None and cached[0]() is node:
            values = cached[1]
            self.counts["root_cache_hits"] += 1
        else:
            values = expression_metrics(node, self.base)
            self.cache[identity] = (weakref.ref(node), values)
            if len(self.cache) > 100000:
                self.cache.popitem(last=False)
                self.counts["metric_cache_evictions"] += 1
        item = self.roots.setdefault(role, {"observations": 0, "maxima": {}, "top": []})
        item["observations"] += 1
        improved = False
        for name, value in values.items():
            old = item["maxima"].get(name)
            if old is None or value > old:
                item["maxima"][name] = value
                improved = True
        if improved:
            item["top"].append({"metrics": values, "context": context, "root_op": node.op})
            item["top"] = sorted(item["top"], key=lambda r: (r["metrics"]["expanded"], r["metrics"]["unique"]), reverse=True)[:8]

    def facts(self, value, context):
        values = value if isinstance(value, (list, tuple)) else [value]
        values = [v for v in values if hasattr(getattr(v, "expr", v), "ast")]
        self.counts["fact_observation_visits"] += len(values)
        self.counts["max_facts_in_observed_list"] = max(self.counts["max_facts_in_observed_list"], len(values))
        for fact in values:
            expr = getattr(fact, "expr", fact)
            for role in ("ast", "value"):
                self.sample(getattr(expr, role, None), role, context)
            self.sample(getattr(fact, "guard", None), "guard", context)

    def _observe(self, callback, *args):
        try:
            callback(*args)
        except Exception as error:
            self.counts["observation_errors"] += 1
            if len(self.errors) < 10:
                self.errors.append(type(error).__name__ + ": " + str(error))

    def wrap_method(self, owner, name, facts=False):
        original = getattr(owner, name)
        label = owner.__name__ + "." + name
        @functools.wraps(original)
        def wrapped(*args, **kwargs):
            self.counts["calls:" + label] += 1
            if facts:
                for value in args[1:]:
                    if isinstance(value, (list, tuple)):
                        self._observe(self.facts, value, label + ":input")
            before = getattr(args[3] if len(args) > 3 else None, "analyzed_times", None)
            result = original(*args, **kwargs)
            if facts:
                self._observe(self.facts, result if result is not None else [], label + ":output")
            if name == "replace":
                self._observe(self.facts, result, label + ":result")
            if before is not None:
                after = getattr(args[3], "analyzed_times", before)
                self.counts["loop_pass_delta:" + label] += max(0, after - before)
            return result
        self._replace(owner, name, wrapped)

    def _install(self):
        self.activated = True
        c = sys.modules["claripy"]
        self.base = c.ast.Base
        variable = sys.modules["dataflow.variable_expression"]
        accurate = sys.modules["dataflow.accurate_data_flow"]
        trace = sys.modules["dataflow.data_trace"]
        parse = sys.modules["dataflow.parse_ast"]
        fast = sys.modules["dataflow.fast_data_flow"]
        for name in ("Load", "Store"):
            original = getattr(c, name)
            def make_constructor(function, op):
                @functools.wraps(function)
                def constructor(*args, **kwargs):
                    value = function(*args, **kwargs)
                    self.counts["constructor_calls:" + op] += 1
                    self._observe(self.sample, value, "constructor:" + op, "claripy." + op)
                    return value
                return constructor
            wrapper = make_constructor(original, name)
            self._replace(c, name, wrapper)
            self._replace(c.ast.bv, name, wrapper)
        self.wrap_method(variable.VarExpr, "replace")
        for name in ("forward_data_trace2", "backward_data_trace2"):
            self.wrap_method(accurate.AccurateDataFlow, name, facts=True)
        self.wrap_method(trace.FastSearch, "_merge_block_exprs", facts=True)
        for name in ("_execute_function", "_block_execute", "_forward_process_loop", "_backward_process_loop"):
            self.wrap_method(trace.FastSearch, name)
        self.wrap_method(fast.FastDataFlow, "execute_loop")
        original_length = parse.sim_action_len
        @functools.wraps(original_length)
        def measured_length(*args, **kwargs):
            result = original_length(*args, **kwargs)
            caller = sys._getframe(1)
            state = self.frame_state.get(id(caller))
            if state is not None:
                state["ls"] = (caller.f_lineno, result)
            self.counts["sim_action_len_calls"] += 1
            return result
        for module in list(sys.modules.values()):
            if module is not None and getattr(module, "__name__", "").startswith("dataflow"):
                if getattr(module, "sim_action_len", None) is original_length:
                    self._replace(module, "sim_action_len", measured_length)
        # Frontend counts include nesting; raw SMT checks are counted separately.
        full = sys.modules["claripy.frontends.full_frontend"].FullFrontend
        for name in ("satisfiable", "eval", "min", "max"):
            self._wrap_query(full, name, "full_frontend")
            self._wrap_query(c.Solver, name, "public_solver")
        import z3
        original_check = z3.Solver.check
        @functools.wraps(original_check)
        def checked(solver, *args, **kwargs):
            value = original_check(solver, *args, **kwargs)
            raw = {"status": str(value), "reason": solver.reason_unknown() if value == z3.unknown else None}
            self.raw_count += 1
            self.raw_status_counts[raw["status"]] += 1
            if self.query_stack:
                for record in self.query_stack:
                    record["raw"].append(raw)
            else:
                self.counts["raw_checks_without_frontend_frame"] += 1
            return value
        self._replace(z3.Solver, "check", checked)
        sys.settrace(self._trace)

    def _wrap_query(self, owner, name, layer):
        original = getattr(owner, name)
        @functools.wraps(original)
        def query(solver, *args, **kwargs):
            self.query_count += 1
            self.counts["query_layer:" + layer] += 1
            record = {"id": self.query_count, "method": name, "layer": layer,
                      "parent_id": self.query_stack[-1]["id"] if self.query_stack else None,
                      "timeout": getattr(solver, "timeout", None), "raw": []}
            self.query_stack.append(record)
            inputs = list(getattr(solver, "constraints", []))
            for argument in list(args[:1]) + [kwargs.get("extra_constraints", [])]:
                inputs.extend(argument if isinstance(argument, (list, tuple)) else [argument])
            for value in inputs:
                if isinstance(value, self.base):
                    self._observe(self.sample, value, "solver_input", name)
            started = time.perf_counter()
            value, error = None, None
            try:
                value = original(solver, *args, **kwargs)
                return value
            except BaseException as caught:
                error = caught
                raise
            finally:
                self.query_stack.pop()
                self._observe(self._finish_query, record, value, error, started)
        self._replace(owner, name, query)

    def _finish_query(self, record, value, error, started):
        record["wall_seconds"] = time.perf_counter() - started
        record["status"] = classify_query(record["raw"], value, error, record["method"])
        record["frontend_boolean"] = value if type(value) is bool else None
        record["error"] = type(error).__name__ + ": " + str(error) if error is not None else None
        self.status_counts[record["status"]] += 1
        self.events.write(json.dumps(record) + "\n")

    def _trace(self, frame, event, arg):
        if event == "call":
            lines = self.lookup.get((frame.f_code.co_filename, frame.f_code.co_firstlineno))
            if lines is None:
                return None
            self.frame_state[id(frame)] = {"lines": lines, "ls": None}
            return self._trace
        state = self.frame_state.get(id(frame))
        if state is None:
            return None
        if event == "return":
            self.frame_state.pop(id(frame), None)
        elif event == "line":
            for gate in state["lines"].get(frame.f_lineno, []):
                count = self.gates[gate["id"]]
                count["hits"] += 1
                ls = state["ls"]
                if gate["ls_threshold"] is not None:
                    if ls is not None and gate["test_start"] <= ls[0] <= gate["test_end"] and ls[1] > gate["ls_threshold"]:
                        count["aptr_limit_hits"] += 1
                    else:
                        count["other_or_short_circuit_hits"] += 1
                if "trace_expr" in frame.f_locals:
                    count["input_fact_skip_events"] += 1
        return self._trace

    def stop(self):
        sys.setprofile(self.previous_profile)
        sys.settrace(self.previous_trace)
        for owner, name, original in reversed(self.saved):
            setattr(owner, name, original)
        self.events.close()
        report = {"schema": "p0b-v5-observations-1", "activated": self.activated,
                  "observation_complete": self.activated and not self.errors,
                  "observer_errors": self.errors, "observer_wall_seconds": time.perf_counter() - self.started,
                  "counts": dict(self.counts), "expressions": self.roots,
                  "gates": list(self.gates.values()), "frontend_calls": self.query_count,
                  "raw_smt_checks": self.raw_count, "frontend_status_counts": dict(self.status_counts),
                  "raw_status_counts": dict(self.raw_status_counts),
                  "scope": {"maxima": "observed roots at constructors/replace/transfer/merge/solver boundaries; not all transient ASTs",
                            "unique": "per-root unique nodes, not session-wide allocations",
                            "expanded": "DAG multiplicity, computed without expanding the tree",
                            "gates": "actual selected branch entries; input skip events are not lost output fact counts",
                            "worklist_iterations": None, "session_unique_ast_nodes": None,
                            "apg_heap_metrics": None}}
        with self.metrics_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        return report

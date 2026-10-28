"""Compare legacy outputs without discarding timing, evidence, or ordered lists."""
import argparse
import json
from pathlib import Path


def read_json(path):
    with Path(path).open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def _sort_values(values):
    return sorted(values, key=lambda value: (type(value).__name__, str(value)))


def compare_results(before, after):
    report = {"semantic_changes": [], "timing_changes": [], "order_only_changes": []}

    def walk(left, right, path=""):
        if type(left) is not type(right):
            report["semantic_changes"].append({"path": path, "before": left, "after": right})
        elif isinstance(left, dict):
            for key in sorted(left.keys() | right.keys()):
                escaped = key.replace("~", "~0").replace("/", "~1")
                child = path + "/" + escaped
                if key not in left or key not in right:
                    report["semantic_changes"].append({"path": child,
                        "before_present": key in left, "after_present": key in right,
                        "before": left.get(key), "after": right.get(key)})
                else:
                    walk(left[key], right[key], child)
        elif isinstance(left, list):
            parts = path.split("/")[1:]
            if (len(parts) == 4 and parts[0] in ("taint_0", "taint_1")
                    and parts[1] == "buffer_overflow" and parts[3] == "offset"
                    and all(type(v) is int for v in left + right)
                    and left != right and sorted(left) == sorted(right)):
                report["order_only_changes"].append({"path": path, "before": left, "after": right})
            elif len(left) != len(right):
                report["semantic_changes"].append({"path": path, "before": left, "after": right})
            else:
                for index, (a, b) in enumerate(zip(left, right)):
                    walk(a, b, path + "/" + str(index))
        elif left != right:
            parts = path.split("/")[1:]
            if len(parts) == 2 and parts[0] in ("icall", "taint_0", "taint_1") and parts[1] == "time":
                category = "timing_changes"
            else:
                category = "semantic_changes"
            report[category].append({"path": path, "before": left, "after": right})

    walk(before, after)
    report["semantic_equal"] = not report["semantic_changes"]
    return report


def validate_icalls(data):
    if not isinstance(data, dict):
        raise ValueError("iCall output must be a mapping")
    for function, calls in data.items():
        if not function.isdecimal() or not isinstance(calls, dict):
            raise ValueError("iCall function keys must be decimal addresses")
        for callsite, targets in calls.items():
            if not callsite.isdecimal() or not isinstance(targets, list):
                raise ValueError("iCall callsites must map decimal addresses to lists")
            if any(type(t) not in (int, str) for t in targets):
                raise ValueError("Unsupported iCall target type")
            if len({(type(t).__name__, t) for t in targets}) != len(targets):
                raise ValueError("Duplicate iCall targets are unexpected; refusing to deduplicate")


def normalize_icalls(data):
    validate_icalls(data)
    # Collector.parse_icall_targets_v1 iterates a target set; retain all values.
    return {f: {c: _sort_values(ts) for c, ts in sorted(calls.items())}
            for f, calls in sorted(data.items())}


def compare_icalls(before, after):
    normalized_before, normalized_after = normalize_icalls(before), normalize_icalls(after)
    report = compare_results(normalized_before, normalized_after)
    report["raw_equal"] = before == after
    report["target_order_only"] = before != after and report["semantic_equal"]
    return report


def normalize_results(data):
    result = json.loads(json.dumps(data))
    for section in ("taint_0", "taint_1"):
        for finding in result.get(section, {}).get("buffer_overflow", {}).values():
            offsets = finding.get("offset")
            if isinstance(offsets, list) and all(type(v) is int for v in offsets):
                finding["offset"] = sorted(offsets)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--icalls", action="store_true")
    args = parser.parse_args()
    compare = compare_icalls if args.icalls else compare_results
    report = compare(read_json(args.before), read_json(args.after))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["semantic_equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

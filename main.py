"""
Offensive IT-Tester — pipeline driver (Layers 1-3 implemented).

  L1 authorization -> L2 reconnaissance -> L3 payload selection

Stops after selection (no payload is fired: execution/detection are later layers).
Prints the payloads the agent WOULD fire at each injection point.

Usage:
  python main.py                         # default sandbox target
  python main.py http://127.0.0.1:8080   # explicit sandbox target
  python main.py http://example.com      # shows the authorization gate rejecting
"""
from __future__ import annotations
import sys
from collections import Counter

from src.authorization.authorize import authorize
from src.recon.recon import discover
from src.intelligence.select import select_all

DEFAULT_TARGET = "http://127.0.0.1:8080"
BAR = "=" * 72


def run(target_url: str, k_per_type: int = 2) -> None:
    print(BAR)
    print(f"OFFENSIVE IT-TESTER   target = {target_url}")
    print(BAR)

    # ---- LAYER 1: authorization ----
    print("\n[LAYER 1] AUTHORIZATION")
    decision = authorize(target_url)
    if not decision.approved:
        print(f"  ✗ REJECTED — {decision.reason}")
        print("\n  Out of scope. Nothing fired. (This is the scope firewall working.)")
        return
    print(f"  ✓ APPROVED — {decision.reason}")

    # ---- LAYER 2: reconnaissance ----
    print("\n[LAYER 2] RECONNAISSANCE")
    points = discover(decision.profile or "dvwa")
    print(f"  {len(points)} injection points discovered:")
    for pt in points:
        print(f"    - {pt.name:14} {pt.short():48} try={','.join(pt.classes)}")

    # ---- LAYER 3: payload selection (stratified by technique) ----
    print("\n[LAYER 3] PAYLOAD SELECTION")
    selection = select_all(points, k_per_type=k_per_type)

    total = 0
    class_counter = Counter()
    techniques_by_class = {}
    for pt, payloads in selection:
        print(f"\n  ▶ {pt.name}  ({pt.method} {pt.param}, bucket={pt.bucket})"
              f"  → {len(payloads)} payloads")
        for p in payloads:
            total += 1
            class_counter[p["attack_class"]] += 1
            techniques_by_class.setdefault(p["attack_class"], set()).add(p["type"])
            flag = "  ⚠ DESTRUCTIVE" if p["is_destructive"] else ""
            print(f"      [{p['id']:9}] {p['attack_class']:4}/{p['type']:16} "
                  f"{p['severity']:8} oracle={p['oracle']:17} {p['payload'][:42]!r}{flag}")

    # ---- summary ----
    print("\n" + BAR)
    print(f"SELECTED {total} payloads across {len(points)} injection points")
    print(f"  by class: {dict(class_counter)}")
    print("  technique coverage (stratified by type):")
    for cls in sorted(techniques_by_class):
        techs = ", ".join(sorted(techniques_by_class[cls]))
        print(f"      {cls:5} → {techs}")
    print("  next layers (not built): governance gate -> fire -> oracle validation")
    print(BAR)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    run(target)

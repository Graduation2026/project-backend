"""Quick verification script for predictor.py changes."""
from src.predictor import (
    is_boilerplate_or_lib, BOILERPLATE_BLACKLIST, SAFE_APIS,
    CWE_MAPPING, UNSAFE_APIS, MAX_CATEGORY_B_FUNCTIONS
)

print(f"BOILERPLATE_BLACKLIST: {len(BOILERPLATE_BLACKLIST)} entries")
print(f"CWE_MAPPING: {len(CWE_MAPPING)} entries")
print(f"UNSAFE_APIS: {len(UNSAFE_APIS)} entries")
print(f"SAFE_APIS: {len(SAFE_APIS)} entries")
print(f"MAX_CATEGORY_B_FUNCTIONS: {MAX_CATEGORY_B_FUNCTIONS}")
print()

# Boilerplate filter tests
tests = [
    ("mainCRTStartup", True),
    ("__asan_report_load", True),
    ("_imp__printf", True),
    ("thunk_FUN_00401000", True),
    ("__GSHandlerCheck", True),
    ("_CxxFrameHandler3", True),
    ("runtime.morestack", True),
    ("__rust_alloc", True),
    ("__cxa_throw", True),
    ("_except_handler4", True),
    ("__clang_call_terminate", True),
    ("my_function", False),
    ("main", False),
    ("process_data", False),
]

print("--- Boilerplate filter tests ---")
all_pass = True
for name, expected in tests:
    result = is_boilerplate_or_lib(name)
    status = "PASS" if result == expected else "FAIL"
    if result != expected:
        all_pass = False
    print(f"  {name}: expected={expected}, got={result}, {status}")

print()

# SAFE vs UNSAFE conflict check
conflict = SAFE_APIS & UNSAFE_APIS
print("--- SAFE_APIS / UNSAFE_APIS conflict check ---")
if conflict:
    print(f"  CONFLICT FOUND: {conflict}")
else:
    print("  No conflicts - clean")

# SAFE vs CWE_MAPPING conflict check (the sscanf bug)
safe_in_cwe = SAFE_APIS & set(CWE_MAPPING.keys())
print()
print("--- SAFE_APIS / CWE_MAPPING conflict check ---")
if safe_in_cwe:
    print(f"  WARNING - safe APIs also in CWE mapping: {safe_in_cwe}")
else:
    print("  No conflicts - clean")

print()
print(f"Overall: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")

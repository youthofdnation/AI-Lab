"""RIAN Commander isolated calculator-test runner.

Restricted acceptance fixture, not a general-purpose sandbox. This script
does not authorize running arbitrary Python code on the owner device.
"""
from pathlib import Path
import ast
import hashlib
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "calculator.py"
TEST = ROOT / "test_calculator.py"
TEST_SHA256 = "6fb38286f1452c6d5745098123c9793e2c62c14248d49284edf5b45cc82b2161"
ALLOWED = (
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Name, ast.Load,
    ast.Store, ast.Expr, ast.Constant, ast.If, ast.BoolOp, ast.Or, ast.Compare,
    ast.Lt, ast.Raise, ast.Call, ast.Assign, ast.BinOp, ast.Mult, ast.Add,
    ast.Return,
)
NAMES = {"subtotal", "tax_rate", "tax_amount", "float", "ValueError"}

def validate(tree):
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("exactly one calculator function required")
    fn = tree.body[0]
    if (fn.name != "total_with_tax" or len(fn.args.args) != 2
            or [a.arg for a in fn.args.args] != ["subtotal", "tax_rate"]
            or fn.decorator_list or fn.args.vararg or fn.args.kwarg):
        raise ValueError("unsupported calculator API")
    for node in ast.walk(tree):
        if type(node) not in ALLOWED:
            raise ValueError("disallowed syntax: " + type(node).__name__)
        if isinstance(node, ast.Name) and node.id not in NAMES:
            raise ValueError("disallowed name: " + node.id)
        if isinstance(node, ast.Call) and (
                not isinstance(node.func, ast.Name)
                or node.func.id != "ValueError"
                or len(node.args) != 1 or node.keywords
                or not isinstance(node.args[0], ast.Constant)
                or not isinstance(node.args[0].value, str)):
            raise ValueError("disallowed function call")
        if isinstance(node, ast.Assign) and (
                len(node.targets) != 1
                or not isinstance(node.targets[0], ast.Name)
                or node.targets[0].id != "tax_amount"):
            raise ValueError("disallowed assignment")
        if isinstance(node, ast.If) and (
                node.orelse or len(node.body) != 1
                or not isinstance(node.body[0], ast.Raise)):
            raise ValueError("unsupported branch")
        if isinstance(node, ast.Constant) and type(node.value) not in (str, int, float):
            raise ValueError("unsupported constant")
    if not isinstance(fn.body[-1], ast.Return):
        raise ValueError("return required")

def main():
    for path in (SOURCE, TEST):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5000:
            raise ValueError("unsafe source or test path")
    source = SOURCE.read_text(encoding="utf-8").replace("\r\n", "\n")
    tests = TEST.read_text(encoding="utf-8").replace("\r\n", "\n")
    if hashlib.sha256(tests.encode("utf-8")).hexdigest() != TEST_SHA256:
        raise ValueError("pinned unittest fixture changed")
    tree = ast.parse(source, filename="calculator.py")
    validate(tree)

    module = types.ModuleType("calculator")
    exec(compile(tree, "calculator.py", "exec"), module.__dict__)
    sys.modules["calculator"] = module
    test_module = types.ModuleType("rian_pinned_unittest")
    exec(compile(tests, "test_calculator.py", "exec"), test_module.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)
    if suite.countTestCases() != 4:
        raise ValueError("unexpected test count")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("RIAN_RUNNER_BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(2)

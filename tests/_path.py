"""Make the skill's scripts/ importable for tests (mirrors what the entry scripts do)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO_ROOT / "code-safety-review"
# ROOT is the skill directory: SKILL.md, scripts/, references/, assets/.
ROOT = PLUGIN_DIR / "skills" / "review"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

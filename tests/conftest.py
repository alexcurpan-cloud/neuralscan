"""Pytest config global — seteaza env inainte de ORICE import din teste.

Fara asta, primul test importat fixeaza NEURALSCAN_DB/ADMIN_KEY, iar
test_audit_log.py (importat mai tarziu) nu mai poate schimba nimic.
"""
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent

os.environ.setdefault('NEURALSCAN_API_KEYS', 'test-key-123')
os.environ.setdefault('NEURALSCAN_ADMIN_KEY', 'admin-test-key-456')
os.environ.setdefault('NEURALSCAN_DB', str(_ROOT / 'test_audit.db'))

# Asigura ca `import audit` (top-level, folosit de app.py) si `import src.audit`
# sunt ACELASI modul in memorie — altfel avem doua instante cu DB_PATH diferite.
sys.path.insert(0, str(_ROOT))
import src.audit as _audit  # noqa: E402
sys.modules['audit'] = _audit
_audit.DB_PATH = Path(os.environ['NEURALSCAN_DB'])
_audit.init_db()

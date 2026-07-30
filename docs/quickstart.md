# NeuralScan Quickstart

## Pornește serverul

```bash
python src/app.py
```

Deschide `http://localhost:5050` în browser.

## Scanează cod

### Din UI
1. Deschide `http://localhost:5050`
2. Paste codul în textarea
3. Click **Check**
4. Citește raportul și copiază fix prompt-ul

### Din CLI
```bash
curl -X POST http://localhost:5050/scan \
  -H 'Content-Type: application/json' \
  -d '{"code": "import os\nos.system(\"ping \" + host)", "filename": "test.py"}'
```

### Exemplu de răspuns
```json
{
  "status": "ok",
  "total": 1,
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
  "findings": [...],
  "report": [
    {
      "severity": "🔴 CRITICAL",
      "titlu": "Shell command built dynamically — injection risk",
      "explicatie": "A system command is built by concatenating user-controlled text...",
      "fix_prompt": "Replace `os.system()`/`subprocess.Popen()` with `subprocess.run()`..."
    }
  ]
}
```

## Rulează testele

```bash
python -m pytest tests/ -v
```

## Scanează un fișier direct

```python
from src.scanner import scan_file
result = scan_file("path/to/your/file.py")
print(result["total"], "issues found")
```

## Structură API

| Endpoint | Method | Descriere |
|----------|--------|-----------|
| `/` | GET | Frontend web |
| `/scan` | POST | Scanează cod |
| `/health` | GET | Health check |

## Dependențe

- Python ≥ 3.10
- flask (opțional pentru API UI)
- pytest (opțional pentru teste)

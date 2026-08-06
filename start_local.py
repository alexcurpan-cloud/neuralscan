"""
Runner local NeuralScan — injecteaza NEURALSCAN_API_KEYS din .secrets.json (workspace)
si porneste serverul. Pe Railway/Procfile, cheia vine din env vars (fara acest script).

Folosire:
    python start_local.py [port]
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
SECRETS = os.path.normpath(os.path.join(HERE, '..', '.secrets.json'))


def load_keys():
    """Citeste NEURALSCAN_API_KEYS din .secrets.json daca exista."""
    if os.path.isfile(SECRETS):
        try:
            with open(SECRETS, encoding='utf-8') as f:
                data = json.load(f)
            keys = data.get('NEURALSCAN_API_KEYS', '')
            if keys:
                return keys
        except Exception as e:
            print(f"[warn] .secrets.json citit cu eroare: {e}")
    return ''


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get('PORT', 5050))
    keys = load_keys()
    if keys:
        os.environ['NEURALSCAN_API_KEYS'] = keys
        print(f"[OK] API keys incarcate din {SECRETS}")
    else:
        print("[warn] FARA API keys (NEURALSCAN_API_KEYS negasit) — doar rate limit per IP.")

    sys.path.insert(0, os.path.join(HERE, 'src'))
    from src.app import app
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    main()

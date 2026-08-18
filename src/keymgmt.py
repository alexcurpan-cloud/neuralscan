"""
keymgmt.py — CLI gestionare chei API (Strat 2).

Comenzi:
    python src/keymgmt.py create --email tester@x.com [--plan pro]
    python src/keymgmt.py revoke --prefix ns_abc123
    python src/keymgmt.py list
    python src/keymgmt.py seed-legacy
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keys  # noqa: E402


def cmd_create(args):
    info = keys.create_key(args.email, args.plan)
    print("CHEIE GENERATA (se afiseaza O SINGURA DATA — nu se mai poate recupera):")
    print()
    print("  " + info["key"])
    print()
    print(f"  prefix: {info['key_prefix']} | plan: {info['plan']} | rate_limit: {info['rate_limit']}/min")
    print("  user:", info["email"])


def cmd_revoke(args):
    ok = keys.revoke_key(args.prefix)
    if ok:
        print(f"OK: cheia {args.prefix}... REVOCATA (401 imediat, fara redeploy).")
    else:
        print(f"ATENTIE: niciun prefix {args.prefix}... gasit sau deja revocat.")


def cmd_list(args):
    rows = keys.list_keys()
    if not rows:
        print("Nicio cheie in DB.")
        return
    print(f"{'id':<4} {'prefix':<12} {'plan':<6} {'rlim':<5} {'revoked':<8} email")
    for r in rows:
        print(f"{r['id']:<4} {r['key_prefix']:<12} {r['plan']:<6} {r['rate_limit']:<5} "
              f"{'DA' if r['revoked'] else 'nu':<8} {r['email']}")


def cmd_seed(args):
    env = os.environ.get('NEURALSCAN_API_KEYS', '')
    n = keys.seed_legacy_env_keys(env)
    print(f"OK: {n} chei legacy din env migrate in DB (user legacy@local).")


def main():
    ap = argparse.ArgumentParser(description="Gestionare chei API NeuralScan (Strat 2)")
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_create = sub.add_parser('create', help='creeaza cheie noua')
    p_create.add_argument('--email', required=True)
    p_create.add_argument('--plan', default='free', choices=['free', 'pro'])
    p_create.set_defaults(fn=cmd_create)

    p_revoke = sub.add_parser('revoke', help='revoca cheie dupa prefix')
    p_revoke.add_argument('--prefix', required=True, help='ex. ns_abc123 (primii 8 chars)')
    p_revoke.set_defaults(fn=cmd_revoke)

    p_list = sub.add_parser('list', help='listeaza cheile')
    p_list.set_defaults(fn=cmd_list)

    p_seed = sub.add_parser('seed-legacy', help='migreaza cheile din env in DB')
    p_seed.set_defaults(fn=cmd_seed)

    args = ap.parse_args()
    keys.init_db()
    args.fn(args)


if __name__ == '__main__':
    main()

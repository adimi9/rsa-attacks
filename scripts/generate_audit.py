"""Prepare the batch-GCD demonstration: 100 synthetic 2048-bit public keys.

Usage:
  python -m scripts.generate_audit
  python -m scripts.generate_audit --keys 100 --extra-pairs 2

The 2048-bit keys are generated ONCE and saved to a public-only JSON
file, so that no key generation is needed during the live presentation.
"""
import argparse
from pathlib import Path
from rsa_lab.fixtures import AUDIT_DEFAULT, DEFAULT, create_audit


def main():
    parser = argparse.ArgumentParser(description='Generate a synthetic public RSA key audit')
    parser.add_argument('--keys', type=int, default=100)
    parser.add_argument('--extra-pairs', type=int, default=2)
    parser.add_argument('--fixture', type=Path, default=DEFAULT)
    parser.add_argument('--out', type=Path, default=AUDIT_DEFAULT)
    args = parser.parse_args()
    path = create_audit(args.out, args.fixture, args.keys, args.extra_pairs)
    print(f'Prepared {args.keys} PUBLIC 2048-bit RSA moduli: {path}')
    print('No private primes or exponents were saved.')


if __name__ == '__main__':
    main()

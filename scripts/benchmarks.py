"""Controlled 2048-bit Fermat experiment; no real-world key scanning.

Usage: python -m scripts.benchmarks
Outputs a CSV to results/fermat_gap_experiment.csv.
"""
import csv
from math import gcd
from pathlib import Path
from time import perf_counter
from sympy import nextprime
from rsa_lab.fixtures import DEFAULT, load, asint
from rsa_lab.attacks.fermat import attack as fermat


def main():
    c=load(DEFAULT)['cases']['fermat']
    baseline=fermat(asint(c['n']),max_iterations=10000)
    assert baseline.success
    p=baseline.p
    rows=[]
    for gap_bits in (480,500,512,516,518,520):
        q=int(nextprime(p+(1<<gap_bits)))
        n=p*q
        if n.bit_length()!=2048 or q.bit_length()!=1024:
            print('Skipping gap',gap_bits,'(would change key size)')
            continue
        start=perf_counter()
        result=fermat(n,max_iterations=40000)
        seconds=perf_counter()-start
        rows.append(dict(modulus_bits=n.bit_length(),gap_bits=gap_bits,
                         observed_gap_bits=(q-p).bit_length(),
                         iterations=result.iterations,success=result.success,
                         seconds=f'{seconds:.6f}'))
        print(rows[-1])
    path=Path(__file__).resolve().parents[1]/'results'/'fermat_gap_experiment.csv'
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print('Saved',path)

if __name__=='__main__':
    main()

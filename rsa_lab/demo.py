"""Four-act RSA lifecycle demo: six weaknesses, two short algorithm extensions."""
from __future__ import annotations
import argparse
import hashlib
import json
import time
from pathlib import Path
from rsa_lab import __version__
from rsa_lab.fixtures import (DEFAULT, AUDIT_DEFAULT, asint, load, create,
                              load_audit, create_audit)
from rsa_lab.mathutils import recover_private, decrypt_bytes, int_to_bytes
from rsa_lab.attacks import fermat, common_prime, batch_gcd, wiener, common_modulus, hastad, crt_fault

ATTACKS = ('fermat','shared_prime','wiener','common_modulus','hastad','crt_fault')
TITLES = {
    'fermat': 'Act I   | Too-close primes: Fermat factorisation',
    'shared_prime': 'Act I   | Shared primes: pairwise GCD -> batch GCD',
    'wiener': 'Act II  | Short private exponent: Wiener',
    'common_modulus': 'Act III | Shared modulus: Bezout recovery',
    'hastad': 'Act III | e=3: single-ciphertext cube root -> Hastad broadcast',
    'crt_fault': 'Act IV  | One faulty RSA-CRT signature: private-key leak',
}


def verify_output(message: bytes, expected_sha256: str) -> bool:
    return hashlib.sha256(message).hexdigest() == expected_sha256


def run_one(name: str, case: dict, audit: dict | None = None) -> dict:
    """Each attack receives only synthetic PUBLIC inputs; no original p/q/d."""
    t0 = time.perf_counter()
    result = {'attack':name,'success':False,'modulus_bits':2048}
    if name == 'fermat':
        n,e,c=map(asint,(case['n'],case['e'],case['c']))
        output=fermat.attack(n,max_iterations=50_000)
        if output.success:
            d=recover_private(n,e,output.p,output.q)
            pt=decrypt_bytes(c,n,d,asint(case['message_bytes']))
            result.update(success=verify_output(pt,case['expected_sha256']),
                          detail=f'Factors found after {output.iterations} Fermat increments; message: {pt.decode()}',
                          work_units=output.iterations, factor_bits=[output.p.bit_length(), output.q.bit_length()], factor_product_verified=True)
        else:
            result['detail']='No factor found within configured iteration budget'
    elif name == 'shared_prime':
        keys=case['public_keys']
        findings=common_prime.attack(keys)
        vulnerable=next((f for f in findings if case['target_id'] in (f['key_a'],f['key_b'])),None)
        if vulnerable:
            target=next(k for k in keys if k['id']==case['target_id'])
            n,e=asint(target['n']),asint(target['e'])
            d=recover_private(n,e,vulnerable['shared_factor'],n//vulnerable['shared_factor'])
            pt=decrypt_bytes(asint(case['ciphertext']),n,d,asint(case['message_bytes']))
            result.update(success=verify_output(pt,case['expected_sha256']),
                          detail=f'{vulnerable["key_a"]} and {vulnerable["key_b"]} share a prime; decrypted: {pt.decode()}',
                          work_units=len(keys)*(len(keys)-1)//2,
                          compromised_keys=sorted({id for f in findings for id in (f['key_a'],f['key_b'])}), shared_factor_bits=vulnerable['shared_factor'].bit_length())
        else:
            result['detail']='No vulnerable target found'

        # A second algorithm for the SAME vulnerability. The four-device
        # example teaches the GCD equation; the 100-key audit teaches the
        # product-tree / remainder-tree batch algorithm.
        if audit is not None:
            audit_keys = audit['public_keys']
            if any(asint(k['n']).bit_length() != 2048 for k in audit_keys):
                raise ValueError('batch audit must contain exact 2048-bit moduli')
            pair_start = time.perf_counter()
            pair_hits = common_prime.attack(audit_keys)
            pair_seconds = time.perf_counter() - pair_start
            pair_factors = {}
            for hit in pair_hits:
                for key_id in (hit['key_a'], hit['key_b']):
                    if key_id in pair_factors and pair_factors[key_id] != hit['shared_factor']:
                        raise ValueError(f'pairwise audit has multiple shared factors: {key_id}')
                    pair_factors[key_id] = hit['shared_factor']
            batch_start = time.perf_counter()
            batch = batch_gcd.attack(audit_keys)
            batch_seconds = time.perf_counter() - batch_start
            agree = (pair_factors == batch.factors and not batch.ambiguous_key_ids)
            result.update(
                success=result['success'] and agree,
                audit_keys=len(audit_keys),
                audit_compromised_keys=sorted(batch.factors),
                audit_vulnerable_count=len(batch.factors),
                audit_pairwise_comparisons=len(audit_keys)*(len(audit_keys)-1)//2,
                audit_pairwise_seconds=round(pair_seconds, 6),
                audit_batch_seconds=round(batch_seconds, 6),
                audit_product_tree_levels=batch.product_tree_levels,
                audit_algorithms_agree=agree,
                audit_ambiguous_keys=list(batch.ambiguous_key_ids),
            )
            result['detail'] += (f' | {len(audit_keys)}-key audit: pairwise and batch GCD '
                                 f'identified the same {len(batch.factors)} compromised keys'
                                 if agree else ' | WARNING: audit algorithms disagree')
    elif name == 'wiener':
        n,e,c=map(asint,(case['n'],case['e'],case['c']))
        output=wiener.attack(n,e)
        if output.success:
            pt=decrypt_bytes(c,n,output.d,asint(case['message_bytes']))
            result.update(success=verify_output(pt,case['expected_sha256']),
                          detail=f'Private exponent recovered ({output.d.bit_length()} bits); decrypted: {pt.decode()}',
                          work_units=output.convergents_examined, private_exponent_bits=output.d.bit_length(), recovered_factor_bits=[output.p.bit_length(), output.q.bit_length()])
        else:
            result['detail']='No valid small private exponent found'
    elif name == 'common_modulus':
        n,e1,e2,c1,c2=map(asint,(case['n'],case['e1'],case['e2'],case['c1'],case['c2']))
        m=common_modulus.attack(n,e1,e2,c1,c2)
        pt=int_to_bytes(m,asint(case['message_bytes']))
        result.update(success=verify_output(pt,case['expected_sha256']),
                      detail=f'Recovered plaintext without private key: {pt.decode()}',work_units=1)
    elif name == 'hastad':
        recipients=case['recipients']
        moduli=[asint(k['n']) for k in recipients]
        ciphertexts=[asint(k['c']) for k in recipients]
        # Introductory e=3 example: one small unpadded message is an exact cube.
        small_case=case['single_ciphertext']
        small_n,small_c=map(asint,(small_case['n'],small_case['c']))
        small_m=hastad.cube_root_attack(small_n,small_c,e=3)
        single_success = (small_m is not None and small_n.bit_length()==2048 and
                          verify_output(int_to_bytes(small_m,asint(small_case['message_bytes'])),
                                        small_case['expected_sha256']))
        # Advanced example: each individual ciphertext is NOT an exact cube.
        individual_roots=[hastad.cube_root_attack(n,c,e=3) for n,c in zip(moduli,ciphertexts)]
        individual_fails=all(root is None for root in individual_roots)
        m=hastad.attack(moduli,ciphertexts,asint(case['e']))
        if m is not None:
            pt=int_to_bytes(m,asint(case['message_bytes']))
            result.update(success=(single_success and individual_fails and verify_output(pt,case['expected_sha256'])),
                          detail=(f'One ciphertext: exact cube root recovered 128-bit demo secret; '
                                  f'long message: single-ciphertext cube roots fail, '
                                  f'but three ciphertexts + CRT recovered {len(pt)} plaintext bytes '
                                  f'(SHA-256 verified; prefix={pt[:34].decode()!r}...)'),
                          work_units=3, single_ciphertext_cube_root_succeeded=single_success,
                          long_message_single_cube_roots_failed=individual_fails,
                          recipient_modulus_bits=[n.bit_length() for n in moduli])
        else:
            result['detail']='CRT result was not a perfect cube'
    elif name == 'crt_fault':
        n,e,m,bad,good=map(asint,(case['n'],case['e'],case['encoded_message'],
                                  case['faulty_signature'],case['good_signature']))
        assert pow(good,e,n)==m and pow(bad,e,n)!=m
        output=crt_fault.attack(n,e,m,bad)
        if output is not None:
            p,q=output
            d=recover_private(n,e,p,q)
            # Proof-of-compromise: recover valid signature from reconstructed key.
            recovered_sig=pow(m,d,n)
            result.update(success=(pow(recovered_sig,e,n)==m),
                          detail=('One injected CRT residue fault -> GCD recovered both factors; '
                                  'recovered key now reproduces a VALID signature'),
                          work_units=1, recovered_factor_bits=[p.bit_length(),q.bit_length()], correct_signature_verified=True, faulty_signature_verified=False)
        else:
            result['detail']='No nontrivial factor from supplied faulty signature'
    else:
        raise ValueError(f'unknown attack: {name}')
    result['seconds']=round(time.perf_counter()-t0,6)
    return result


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description='six real-sized 2048-bit RSA attack demonstrations')
    parser.add_argument('--attack',choices=['all',*ATTACKS],default='all')
    parser.add_argument('--fixture',type=Path,default=DEFAULT)
    parser.add_argument('--audit-fixture',type=Path,default=AUDIT_DEFAULT,
                        help='public-only 100-key batch-GCD audit (used for shared_prime)')
    parser.add_argument('--fresh',action='store_true',help='regenerate fresh synthetic 2048-bit cases before attacking')
    parser.add_argument('--json-out',type=Path,help='optional machine-readable result file')
    parser.add_argument('--no-pause',action='store_true',help='disable step-by-step enter prompts')
    parser.add_argument('--verbose',action='store_true',help='show extra cryptographic verification evidence')
    args=parser.parse_args(argv)
    if args.fresh or not args.fixture.exists():
        print('[setup] Generating synthetic 2048-bit fixture set (may take a while)...', flush=True)
        create(args.fixture)
    fixture=load(args.fixture)
    if fixture.get('metadata',{}).get('bits') != '0x800':
        raise ValueError('expected 2048-bit fixture metadata')
    selected=ATTACKS if args.attack=='all' else (args.attack,)
    audit = None
    if 'shared_prime' in selected:
        if args.fresh or not args.audit_fixture.exists():
            print('[setup] Generating the public 100-key audit (offline preparation)...',flush=True)
            create_audit(args.audit_fixture,args.fixture)
        audit = load_audit(args.audit_fixture)
    print('\n' + '='*72)
    print(f'RSA LIFECYCLE LAB  v{__version__} | FOUR acts | SIX weaknesses | 2048-bit moduli')
    print('Extensions: pairwise -> batch GCD; single cube root -> Hastad broadcast')
    print('Synthetic WEAK cases ONLY — no full-strength RSA is broken')
    print('='*72)
    records=[]
    for i,name in enumerate(selected,1):
        if not args.no_pause and i>1:
            try: input('\n[Enter] Next attack ...')
            except EOFError: pass
        case=fixture['cases'][name]
        res=run_one(name,case,audit if name=='shared_prime' else None)
        records.append(res)
        print(f'\n{i}. {TITLES[name]}')
        print(f'   Modulus: {res["modulus_bits"]} bits | Success: {"YES" if res["success"] else "NO"}')
        print(f'   Evidence: {res["detail"]}')
        print(f'   Elapsed: {res["seconds"]:.6f}s',flush=True)
        if name=='shared_prime' and audit is not None:
            print(f'   Public key audit: {res["audit_keys"]} x 2048-bit moduli | '
                  f'{res["audit_vulnerable_count"]} compromised keys')
            print(f'   Pairwise: {res["audit_pairwise_comparisons"]} comparisons, '
                  f'{res["audit_pairwise_seconds"]:.6f}s | '
                  f'Batch (product/remainder trees): {res["audit_batch_seconds"]:.6f}s')
            print(f'   Factor results match: {res["audit_algorithms_agree"]}')
        if args.verbose:
            for field in ('work_units','factor_bits','factor_product_verified','shared_factor_bits','compromised_keys','private_exponent_bits','recovered_factor_bits','recipient_modulus_bits','correct_signature_verified','faulty_signature_verified','single_ciphertext_cube_root_succeeded',
                          'long_message_single_cube_roots_failed','audit_product_tree_levels',
                          'audit_compromised_keys','audit_ambiguous_keys'):
                if field in res:
                    print(f'   {field}: {res[field]}')
    print('\n'+'='*72)
    print(f'RESULTS: {sum(r["success"] for r in records)} / {len(records)} demonstrations verified')
    print('A success means the intentionally flawed lab case was compromised.')
    print('It does NOT mean normal 2048-bit RSA keys are breakable.')
    print('='*72)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        print(f'Results written to {args.json_out}')
    return 0 if all(r['success'] for r in records) else 1

if __name__=='__main__':
    raise SystemExit(main())

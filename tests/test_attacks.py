"""Regression checks: actual 2048-bit fixture data and negative controls."""
import json
import unittest
from math import gcd
from pathlib import Path
from rsa_lab.demo import run_one, ATTACKS
from rsa_lab.fixtures import DEFAULT, AUDIT_DEFAULT, asint
from rsa_lab.attacks import fermat, common_prime, batch_gcd, wiener, common_modulus, hastad, crt_fault
from rsa_lab.mathutils import egcd, cube_root_exact, modinv


class TestMath(unittest.TestCase):
    def test_egcd(self):
        g,a,b=egcd(65537,17)
        self.assertEqual(g,1)
        self.assertEqual(a*65537+b*17,1)

    def test_fermat_tiny(self):
        r=fermat.attack(7*11,max_iterations=10)
        self.assertTrue(r.success)
        self.assertEqual((r.p,r.q),(7,11))

    def test_wiener_tiny(self):
        r=wiener.attack(90581,17993)
        self.assertEqual(r.d,5)
        self.assertEqual(r.p*r.q,90581)

    def test_integer_roots(self):
        self.assertEqual(cube_root_exact(9**3),9)
        self.assertIsNone(cube_root_exact(9**3-1))

    def test_small_public_exponent_cube_root(self):
        self.assertEqual(hastad.cube_root_attack(1009, 5**3), 5)
        self.assertIsNone(hastad.cube_root_attack(1009, 11**3 % 1009))

    def test_batch_gcd_product_remainder_tree_odd_count(self):
        p, q, r, s, t = 101, 103, 107, 109, 113
        keys = [dict(id='A', n=p*q), dict(id='B', n=p*r), dict(id='C', n=s*t)]
        out = batch_gcd.attack(keys)
        self.assertEqual(out.factors, {'A':p, 'B':p})
        self.assertFalse(out.ambiguous_key_ids)
        self.assertGreaterEqual(out.product_tree_levels, 2)

    def test_batch_gcd_reports_both_factors_shared_ambiguity(self):
        p, q, r, s = 101, 103, 107, 109
        keys = [dict(id='A', n=p*q), dict(id='B', n=p*r), dict(id='C', n=q*s)]
        out = batch_gcd.attack(keys)
        # A shares p with B and q with C; the batch formula yields g_A=n_A.
        # Honest behaviour: flag ambiguity instead of claiming factorisation.
        self.assertIn('A', out.ambiguous_key_ids)
        self.assertNotIn('A', out.factors)
        self.assertEqual(out.factors['B'], p)
        self.assertEqual(out.factors['C'], q)

    def test_batch_gcd_with_no_shared_factors(self):
        out = batch_gcd.attack([dict(id='a',n=101*103), dict(id='b',n=107*109)])
        self.assertFalse(out.factors)
        self.assertFalse(out.ambiguous_key_ids)


class TestRealSized(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(DEFAULT.read_text(encoding='utf-8'))['cases']

    def test_all_six_attacks(self):
        for name in ATTACKS:
            with self.subTest(attack=name):
                r=run_one(name,self.data[name])
                self.assertTrue(r['success'],r)
                self.assertEqual(r['modulus_bits'],2048)

    def test_every_modulus_is_exactly_2048_bits(self):
        for name,case in self.data.items():
            if name=='shared_prime':
                values=[asint(k['n']) for k in case['public_keys']]
            elif name=='hastad':
                values=[asint(k['n']) for k in case['recipients']]
                values.append(asint(case['single_ciphertext']['n']))
            else:
                values=[asint(case['n'])]
            self.assertTrue(all(n.bit_length()==2048 for n in values),name)

    def test_cube_root_then_hastad_both_2048_bit(self):
        c = self.data['hastad']
        simple = c['single_ciphertext']
        n, cipher = asint(simple['n']), asint(simple['c'])
        self.assertEqual(n.bit_length(), 2048)
        root = hastad.cube_root_attack(n, cipher)
        self.assertIsNotNone(root)
        self.assertEqual(root**3, cipher)
        moduli = [asint(k['n']) for k in c['recipients']]
        ciphers = [asint(k['c']) for k in c['recipients']]
        self.assertTrue(all(hastad.cube_root_attack(m, x) is None
                            for m, x in zip(moduli, ciphers)))
        self.assertIsNotNone(hastad.attack(moduli, ciphers))

    def test_100_key_batch_audit_matches_pairwise(self):
        audit = json.loads(AUDIT_DEFAULT.read_text(encoding='utf-8'))
        keys = audit['public_keys']
        self.assertEqual(len(keys), 100)
        self.assertTrue(all(asint(k['n']).bit_length()==2048 for k in keys))
        base = {k['id']: k['n'] for k in self.data['shared_prime']['public_keys']}
        observed = {k['id']: k['n'] for k in keys}
        self.assertTrue(all(observed[id] == n for id,n in base.items()))
        pair = common_prime.attack(keys)
        pair_factors = {id: x['shared_factor'] for x in pair for id in (x['key_a'],x['key_b'])}
        batched = batch_gcd.attack(keys)
        self.assertEqual(batched.factors, pair_factors)
        self.assertEqual(len(batched.factors), 6)
        self.assertFalse(batched.ambiguous_key_ids)
        for key in keys:
            if key['id'] in batched.factors:
                factor = batched.factors[key['id']]
                self.assertEqual(asint(key['n']) % factor, 0)
                self.assertTrue(1 < factor < asint(key['n']))
        summary = run_one('shared_prime', self.data['shared_prime'], audit)
        self.assertTrue(summary['success'])
        self.assertTrue(summary['audit_algorithms_agree'])
        self.assertEqual(summary['audit_pairwise_comparisons'], 4950)

    def test_fermat_fails_within_budget_on_unrelated_key(self):
        clean=next(k for k in self.data['shared_prime']['public_keys'] if k['id']=='office-C')
        result=fermat.attack(asint(clean['n']),max_iterations=300)
        self.assertFalse(result.success)

    def test_only_intended_shared_prime_pair(self):
        hits=common_prime.attack(self.data['shared_prime']['public_keys'])
        pairs={frozenset((x['key_a'],x['key_b'])) for x in hits}
        self.assertEqual(pairs,{frozenset(('sensor-A','sensor-B'))})

    def test_normal_exponent_not_wiener_vulnerable(self):
        clean=next(k for k in self.data['shared_prime']['public_keys'] if k['id']=='office-C')
        r=wiener.attack(asint(clean['n']),asint(clean['e']))
        self.assertFalse(r.success)

    def test_broadcast_requires_same_message(self):
        c=self.data['hastad']
        ns=[asint(k['n']) for k in c['recipients']]
        original_cs=[asint(k['c']) for k in c['recipients']]
        # Alter one recipient's ciphertext by encrypting a DIFFERENT message.
        altered=list(original_cs)
        altered[2]=pow(123456789,3,ns[2])
        self.assertIsNone(hastad.attack(ns,altered,e=3))

    def test_fault_requires_faulty_signature(self):
        c=self.data['crt_fault']
        n,e,m=map(asint,(c['n'],c['e'],c['encoded_message']))
        good=asint(c['good_signature'])
        self.assertIsNone(crt_fault.attack(n,e,m,good))
        bad=asint(c['faulty_signature'])
        factors=crt_fault.attack(n,e,m,bad)
        self.assertIsNotNone(factors)
        self.assertEqual(factors[0]*factors[1],n)

    def test_common_modulus_both_ciphers_match_recovered_message(self):
        c=self.data['common_modulus']
        n,e1,e2,c1,c2=map(asint,(c['n'],c['e1'],c['e2'],c['c1'],c['c2']))
        m=common_modulus.attack(n,e1,e2,c1,c2)
        self.assertEqual(pow(m,e1,n),c1)
        self.assertEqual(pow(m,e2,n),c2)

    def test_wiener_recovers_actual_factorisation(self):
        c=self.data['wiener']
        n,e=map(asint,(c['n'],c['e']))
        r=wiener.attack(n,e)
        self.assertEqual(r.p*r.q,n)
        self.assertEqual((e*r.d-1)%((r.p-1)*(r.q-1)),0)


if __name__=='__main__':
    unittest.main()

import unittest
import pickle
from unittest.mock import patch
from dataclasses import asdict,replace,fields
from test_p3_contracts import fixture


class ScopeHashTests(unittest.TestCase):
    def test_hash_matches_value_fields_and_does_not_rehash_nested_identities(self):
        scope=replace(fixture()[4],session_id='hash-cache-test')
        cls=type(scope.function);original=cls.__hash__;calls=[]
        def counted(value):calls.append(value);return original(value)
        with patch.object(cls,'__hash__',counted):
            expected=hash(tuple(getattr(scope,field.name) for field in fields(scope)))
            first=hash(scope);count=len(calls)
            for _ in range(32):self.assertEqual(hash(scope),expected)
            self.assertEqual(first,expected)
            self.assertEqual(len(calls),count)

    def test_hash_cache_is_not_wire_data_or_persisted_pickle_identity(self):
        scope=replace(fixture()[4],session_id='hash-cache-wire')
        before=asdict(scope);hash(scope)
        self.assertEqual(asdict(scope),before)
        restored=pickle.loads(pickle.dumps(scope))
        self.assertEqual(restored,scope)
        self.assertNotIn('_stable_hash',vars(restored))
        self.assertEqual(hash(restored),hash(scope))
        changed=replace(scope,state_revision=scope.state_revision+1)
        self.assertEqual(hash(changed),hash(tuple(getattr(changed,field.name) for field in fields(changed))))

# -*- coding: utf-8 -*-
import os
import json
import unittest

# dut
import signedjson

def _(name):
    f = open(os.path.dirname(__file__) + '/data/' + name, 'r')
    rv = f.read()
    f.close()
    return rv
    
class Test_BasicSignVerify(unittest.TestCase):
    def test_sign(self):
        j = signedjson.sign(_('signed.json'), _('privkey.der'), 'me')
        self.assertTrue('signatures' in j)
        
    def test_sign_with_extra(self):
        j = signedjson.sign(_('signed.json'), _('privkey.der'), 'me', ['baz'])
        self.assertTrue('signatures' in j)
        
    def test_verify(self):
        self.assertTrue(signedjson.verify(_('signed.json')))
        
    def test_verify_with_extra(self):
        self.assertTrue(signedjson.verify(_('signed_extra_baz.json')))
        
    def test_verify_negative(self):
        self.assertFalse(signedjson.verify(_('signed_BADSIG.json')))
        
    def test_verify_with_extra_negative(self):
        self.assertFalse(signedjson.verify(_('signed_extra_baz_BADSIG.json')))
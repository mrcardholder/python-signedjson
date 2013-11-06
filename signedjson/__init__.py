# -*- coding: utf-8 -*-
#
import json
import hashlib
import binascii

from bitcoin.key import CKey

class BadJSONError(Exception):
    '''raised when JSON is not suitable for sign/verify'''
    def __init__(self, msg):
        self.msg = msg

    def __repr__(self):
        return repr(self.msg)

    __str__ = __repr__

    __unicode__ = __repr__

# @private
def sign(jsonbuf, privkey, role, extra_keys=[]):
    '''
    :type jsonbuf: str.
    :param privkey: private key in DER form
    :type privkey: str.
    :type role: str.
    :type extra_keys: list.
    :returns: dict - JSON with signature appended.
    :raises: BadJSONError
    '''
    jsondoc = json.loads(jsonbuf)
    signed_keys = jsondoc.get('signed_keys', [])
    sigdict = {}
    for key in signed_keys + extra_keys:
        # FIXME:в ключе допустимы только [a-zA-Z0-9_.\-]
        # FIXME:можно исключить числа с плавающей точкой
        value = jsondoc.get(key, None)
        if not value:
            raise BadJSONError('Missing attribute: %s' % (repr(key),))
        sigdict[key] = value
        
    if not len(sigdict):
        raise BadJSONError('No attributes to sign')

    instr = json.dumps(sigdict, separators=(',',':'), sort_keys=True)
    hash = hashlib.sha256(hashlib.sha256(instr).digest()).digest()
    
    ckey = CKey()
    ckey.set_privkey(privkey)
    signed = ckey.sign(hash)
    
    sigentry = {
        'role': role,
        'signature_type': 'secp256k1',
        'pubkey': binascii.hexlify(ckey.get_pubkey()),
        'signature': binascii.hexlify(signed)
    }
    if extra_keys:
        sigentry['extra_signed_keys'] = extra_keys
       
    jsondoc.setdefault('signatures', []).append(sigentry)
    
    return jsondoc

def verify(jsonbuf):
    '''
    :param jsondoc: str with JSON
    :type jsondoc: str
    returns: bool - True if signature verification succeeds
    :raises: BadJSONError
    '''
    basedict = {}
    jsondoc = json.loads(jsonbuf)
    signatures = jsondoc.get('signatures', [])
    
    if not len(signatures):
        raise BadJSONError('Signatures not found')
    
    for key in jsondoc.get('signed_keys', []):
        value = jsondoc.get(key, None)
        if not value:
            raise BadJSONError('Missing attribute: %s' % (repr(key),))
        basedict[key] = value
        
    ckey = CKey()
    sigchecks = []
    for signature_dict in signatures:
        if 'secp256k1' != signature_dict.get('signature_type', ''):
            continue
        sig = binascii.unhexlify(signature_dict.get('signature', ''))
        pubkey = binascii.unhexlify(signature_dict.get('pubkey', ''))
        sigdict = {}
        for key in signature_dict.get('extra_signed_keys', []):
            value = jsondoc.get(key, None)
            if not value:
                raise BadJSONError('Missing attribute: %s' % (repr(key),))
            sigdict[key] = value
        sigdict.update(basedict)
        ckey.set_pubkey(pubkey)
        instr = json.dumps(sigdict, separators=(',',':'), sort_keys=True)
        hash = hashlib.sha256(hashlib.sha256(instr).digest()).digest()
        sigchecks.append(ckey.verify(hash, sig))
        
    return (sigchecks and 0 not in sigchecks and -1 not in sigchecks)

__all__ = ["sign", "verify", "BadJSONError"]


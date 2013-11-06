# -*- coding: utf-8 -*-
import argparse
import binascii
import json

import signedjson

if '__main__' == __name__:
    parser = argparse.ArgumentParser(description='Sign/verify JSON documents.')
    parser.add_argument('-a', '--action', choices=['sign','verify'],
            default='sign', help="Action: sign/verify given input")
    parser.add_argument('-i', '--infile', metavar="infile", required=1,
            type=argparse.FileType('r'), help="Input JSON")
    parser.add_argument('-k', '--keyfile', metavar="keyfile", required=0,
            type=argparse.FileType('r'), help="Key in DER form")
    parser.add_argument('-e', '--extrakeys', metavar="extrakeys", nargs='+',
            help="Extra key names to be signed")
    parser.add_argument('-r', '--role', metavar="role", type=str, help="Role")
    args = parser.parse_args()

    if 'sign' == args.action:
        if not args.role:
            print 'ERROR: --role argument required'
            parser.print_help()
            exit(1)
        if not args.keyfile:
            print 'ERROR: --keyfile argument required'
            parser.print_help()
            exit(1)
        ek = [] if not args.extrakeys else args.extrakeys
        j = signedjson.sign(
            args.infile.read(), args.keyfile.read(), args.role, extra_keys=ek)
        print json.dumps(j)
    elif 'verify' == args.action:
        rv = signedjson.verify(args.infile.read())
        print bool(rv)
    else:
        parser.print_help()

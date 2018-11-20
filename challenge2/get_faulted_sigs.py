from hashlib import sha256
import os

import requests

from gravitysphincs import *


faulted_signatures = set()
sigs = {}

# real sig = 20a9659cf59426dc3310df014126f1be33872b593a5413a7e7a46471e71d5257


def get_faulted_signatures():
    msg = "All your base are belong to us"

    # public_key = bytes.fromhex("e4e8d1630f82d20c6f9b77723c6464fd9048bfbab879988c00c7161833fdfaaf")
    # digest = sha256(msg.encode()).digest()

    # layer = GRAVITY_d - 1
    if not os.path.exists("signatures"):
        os.mkdir("signatures")

    num_sigs = 0
    while num_sigs < 200:
        req = requests.post("https://cryptochall.ks.kgc.io/chall2/sign",
                            json={"data": msg})
        signature_data = bytes.fromhex(req.text)
        md = sha256(signature_data).digest()

        req2 = requests.post("https://cryptochall.ks.kgc.io/chall2/verify",
                             json={"data": msg, "signature": req.text})
        print(req2.text)

        with open(os.path.join("signatures", md.hex()), "wb") as f:
            f.write(signature_data)

        if md in sigs:
            sigs[md] += 1
        else:
            sigs[md] = 1
        num_sigs += 1

        print(num_sigs)

    for sig in sigs:
        print(sig.hex(), sigs[sig])


def sort_signatures():
    num_sig = 0
    layer = GRAVITY_d - 1

    f = open(os.path.join("signatures", "20a9659cf59426dc3310df014126f1be33872b593a5413a7e7a46471e71d5257"), "rb")
    real_sig = gravity_unserialize_signature(f)
    f.close()

    wots_sig = real_sig.merkle[layer].wots_signature
    real_wots_sig = b''.join(wots_sig)

    for filename in os.listdir("signatures"):
        if filename == "attack":
            continue
        with open(os.path.join("signatures", filename), "rb") as f:
            sig = gravity_unserialize_signature(f)

        s = sig.merkle[GRAVITY_d - 1].wots_signature
        if b''.join(s) != real_wots_sig:
            print(num_sig)

            g = open(os.path.join("signatures\\attack", filename), "wb")
            gravity_serialize_signature(g, sig)
            g.close()
            num_sig += 1


if __name__ == "__main__":
    # sort_signatures()
    get_faulted_signatures()

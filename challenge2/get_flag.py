from hashlib import sha256
import io

import requests

from gravitysphincs import *
from forge_signature import forge_signature, get_wots_private_keys


FAULTED_SIGNATURES_PATH = "signatures/attack"
REAL_SIGNATURE_FILE = "signatures/20a9659cf59426dc3310df014126f1be33872b593a5413a7e7a46471e71d5257"


def main():
    # Public key for the challenge
    with open("key.pub") as f:
        public_key = bytes.fromhex(f.read())

    # Message for which the signatures have been generated
    msg = sha256("All your base are belong to us".encode()).digest()
    layer = GRAVITY_d - 1  # We attack the penultimate layer

    wots_private_key = get_wots_private_keys(msg, FAULTED_SIGNATURES_PATH, layer)
    if wots_private_key is None:
        print("Private key not rebuilt, more faulted signatures are needed.")
        return

    # Retrieve the message to be signed
    req = requests.get("https://cryptochall.ks.kgc.io/chall2/flag")

    # Forge a signature for the wanted message
    forged_msg = sha256(req.text.encode()).digest()
    sig = gravity_unserialize_signature(open(REAL_SIGNATURE_FILE, "rb"))
    forged_sig = forge_signature(forged_msg, msg, sig, wots_private_key, layer)

    assert gravity_verify(public_key, forged_sig, forged_msg)

    # gravity_serialize_signature(open("forged.txt", "wb"), forged_sig)
    signature_data = io.BytesIO()
    gravity_serialize_signature(signature_data, forged_sig)
    signature_data.seek(0)

    # Send forged signature to the server and win
    sig = signature_data.read().hex()
    req = requests.post("https://cryptochall.ks.kgc.io/chall2/win",
                        json={"data": req.text, "signature": sig})
    print(req.text)


if __name__ == "__main__":
    main()

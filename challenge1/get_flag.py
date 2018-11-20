import requests

from eddsa import *


def retrieve_private_key(msg: bytes, public_key: bytes, real_sig: bytes, fake_sig: bytes) -> bytes:
    def inverse(xx: int):
        return pow(xx, l-2, l)  # works as l is prime

    assert checkvalid(real_sig, msg, public_key)

    r1, s1 = decodepoint(real_sig[:32]), decodeint(real_sig[32:])
    r2, s2 = decodepoint(fake_sig[:32]), decodeint(fake_sig[32:])

    t1 = Hint(encodepoint(r1) + public_key + msg)
    t2 = Hint(encodepoint(r2) + public_key + msg)
    a = (s1 - s2) * inverse(t1 - t2) % l
    return a.to_bytes(32, 'big')


def signature2(m: bytes, sk: bytes, pk: bytes) -> bytes:
    a = int.from_bytes(sk, 'big')
    r = Hint(b'\x00' * 32 + m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def main():
    public_key = bytes.fromhex("fe4773800b7e321fc33a4ae25cc0540c55bd412dcd5cba683d1ff2c7c2e14b9c")

    # Compute private key from real and faulted signature for a test message
    m = "000000"
    real_sig = bytes.fromhex("fe1f44347edb2f3561c4a04ef723d26937329e72a9e7d85a39c2f081b09f8e29a086c6dad6c6d3a9d235d2b5ece309797e4490a91c01c5396dc14a7291e1de04")
    fake_sig = bytes.fromhex("ca885d387ccbb150663f1580b87294849ed1cbb393aad52ced8d9f9f005f0a13cdb22ecaf52db824052ac30c0d1fce5bbb65a05b219cc589838f4884508b2603")
    private_key = retrieve_private_key(m.encode(), public_key, real_sig, fake_sig)
    print(int.from_bytes(private_key, 'big'))

    # Generate a signature for the challenge message
    flag_msg = "I find your lack of faith disturbing"
    forged_sig = signature2(flag_msg.encode(), private_key, public_key)
    assert checkvalid(forged_sig, flag_msg.encode(), public_key)

    # Get flag
    req = requests.post("https://cryptochall.ks.kgc.io/chall1/win",
                        json={"data": flag_msg, "signature": forged_sig.hex()})
    print("Flag: " + req.text)


if __name__ == "__main__":
    main()

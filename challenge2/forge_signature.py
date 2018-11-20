import os

from gravitysphincs import *


def extract_merkle_root(layer: int, signature: GravitySignature, msg: bytes):
    addr, subset = pors_randsubset(signature.rand, msg)
    msg = octoporst_extract(signature.op_sign, subset)

    address = Address(GRAVITY_d, addr)
    for i in range(layer):  # layer we attack
        address.layer -= 1
        pk = merkle_extract(address, signature.merkle[i], msg)
        msg = pk
        address.index >>= MERKLE_h
    return msg


def wots_indices_from_msg(msg: bytes):
    msg_indices = []
    for v in msg:
        msg_indices.append(v >> 4 & 0xf)
        msg_indices.append(v & 0xf)
    checksum = sum([WOTS_w - 1 - c for c in msg_indices])

    for i in range(WOTS_ell1, WOTS_ell):
        msg_indices.append(checksum & 0xf)
        checksum >>= 4
    return msg_indices


def extract_wots_private_keys_from_sig(layer: int, signature: GravitySignature, msg: bytes):
    private_keys = [None] * WOTS_ell

    msg = extract_merkle_root(layer, signature, msg)
    msg_indices = wots_indices_from_msg(msg)

    wots_sig = signature.merkle[layer].wots_signature
    for i in range(WOTS_ell - 1):
        if msg_indices[i] == 0:
            private_keys[i] = wots_sig[i]

    # special case for last checksum nibble, as it is very unlikely to get a 0 in this case.
    # we assume 1 will be sufficient in most cases.
    if msg_indices[WOTS_ell - 1] == 1:
        private_keys[WOTS_ell - 1] = wots_sig[WOTS_ell - 1]
    return private_keys


def get_wots_private_keys(msg: bytes, signature_path: str, layer: int) -> List[bytes]:
    # retrieve WOTS private key from faulted signatures
    wots_private_key = [None] * WOTS_ell
    num_signatures = 0

    for filename in os.listdir(signature_path):
        num_signatures += 1
        with open(os.path.join(signature_path, filename), "rb") as f:
            sig = gravity_unserialize_signature(f)

        priv = extract_wots_private_keys_from_sig(layer, sig, msg)
        for i in range(len(priv)):
            if priv[i] is not None:
                wots_private_key[i] = priv[i]

        if None not in wots_private_key:
            break

    if None in wots_private_key:
        raise Exception("Private key not rebuilt, more faulted signatures are needed.")

    print("Private key recovered with {:} faulted signatures.".format(num_signatures))
    return wots_private_key


def wots_forge_sign(private_key, msg) -> WotsSign:
    checksum = 0
    signature = []

    for i in range(0, WOTS_ell1, 2):
        v = msg[i // 2]
        a, b = (v >> 4) & 0xf, v & 0xf
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)

        signature.append(wots_chain(private_key[i], a))
        signature.append(wots_chain(private_key[i + 1], b))

    for i in range(WOTS_ell1, WOTS_ell - 1):
        signature.append(wots_chain(private_key[i], checksum & 0xf))
        checksum >>= 4

    # special case for last checksum nibble
    signature.append(wots_chain(private_key[WOTS_ell - 1], (checksum & 0xf) - 1))
    return tuple(signature)


def forge_random_seed(msg: bytes, layer: int, fts_index: int) -> bytes:
    while True:
        random_seed = os.urandom(32)
        addr, _ = pors_randsubset(random_seed, msg)

        addr >>= MERKLE_h * layer
        index = addr & (MERKLE_hhh - 1)
        if index == fts_index:
            break
    return random_seed


def forge_signature(msg: bytes, original_msg: bytes, signature: GravitySignature,
                    wots_private_keys: List[bytes],
                    layer: int) -> GravitySignature:
    # get FTS index to obtain in the attacked layer
    addr, subset = pors_randsubset(signature.rand, original_msg)
    addr >>= MERKLE_h * layer
    fts_index = addr & (MERKLE_hhh - 1)

    while True:
        # forge a random seed to obtain the correct FTS index for the message to sign
        signature.rand = forge_random_seed(msg, layer, fts_index)
        try:
            msg_to_sign = extract_merkle_root(layer, signature, msg)
        except AssertionError:
            continue

        wots_sig = wots_forge_sign(wots_private_keys, msg_to_sign)
        signature.merkle[layer].wots_signature = wots_sig
        break
    return signature

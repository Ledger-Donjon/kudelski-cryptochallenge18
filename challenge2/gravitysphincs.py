from dataclasses import dataclass
from typing import List, Tuple, Set

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from haraka_fast import haraka256, haraka512
except OSError:
    from haraka import haraka256, haraka512

# Parameters for the CTF
MERKLE_h = 5
PORS_k = 32
GRAVITY_d = 7
GRAVITY_c = 0


GRAVITY_ccc = 1 << GRAVITY_c
HASH_SIZE = 32
MERKLE_hhh = 1 << MERKLE_h
GRAVITY_h = MERKLE_h * GRAVITY_d + GRAVITY_c

if GRAVITY_h < 64:
    GRAVITY_mask = ~(0xFFFFFFFFFFFFFFFF << GRAVITY_h)
else:
    GRAVITY_mask = 0xFFFFFFFFFFFFFFFF
PORS_tau = 16
PORS_t = 1 << PORS_tau


WotsSign = Tuple[bytes, ...]
PorsSign = Tuple[bytes, ...]


@dataclass
class Address:
    layer: int = 0
    index: int = 0


@dataclass
class MerkleSignature:
    wots_signature: WotsSign
    auth: Tuple[bytes, ...]


@dataclass
class OctoporstSignature:
    s: PorsSign
    octopus: Tuple[bytes, ...]  # PORS_k * PORS_tau elements
    octolen: int


@dataclass
class GravitySignature:
    rand: bytes
    op_sign: OctoporstSignature
    merkle: Tuple[MerkleSignature, ...]


@dataclass
class GravityPrivateKey:
    seed: bytes
    salt: bytes
    cache: Tuple[bytes, ...]


WOTS_LOG_ell1 = 6
WOTS_ell1 = 1 << WOTS_LOG_ell1
WOTS_chksum = 3
WOTS_ell = WOTS_ell1 + WOTS_chksum
WOTS_w = 16


def ltree(buf, count) -> bytes:
    while count > 1:
        buf2 = []
        new_count = count >> 1
        for i in range(new_count):
            buf2.append(haraka512(buf[2*i]+buf[2*i+1]))
        if count & 1:
            buf2.append(buf[-1])
            new_count += 1
        buf = buf2
        count = new_count
    return buf[0]


def wots_chain(msg: bytes, count: int) -> bytes:
    for i in range(count):
        msg = haraka256(msg)
    return msg


def wots_gensk(key: bytes, address: Address) -> Tuple[bytes, ...]:
    counter = address.index.to_bytes(8, 'big') + address.layer.to_bytes(4, 'big') + b'\x00\x00\x00\x00'

    cipher = Cipher(algorithms.AES(key), modes.CTR(counter), backend=default_backend())
    encryptor = cipher.encryptor()

    wots_private_key = []
    for i in range(WOTS_ell):
        wots_private_key.append(encryptor.update(b'\x00' * HASH_SIZE))
    return tuple(wots_private_key)


def wots_sign(private_key, msg) -> WotsSign:
    checksum = 0
    signature = []

    for i in range(0, WOTS_ell1, 2):
        v = msg[i // 2]
        a, b = (v >> 4) & 0xf, v & 0xf
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)

        signature.append(wots_chain(private_key[i], a))
        signature.append(wots_chain(private_key[i + 1], b))

    for i in range(WOTS_ell1, WOTS_ell):
        signature.append(wots_chain(private_key[i], checksum & 0xf))
        checksum >>= 4

    return tuple(signature)


def lwots_ltree(pk) -> bytes:
    buf = [c for c in pk]
    return ltree(buf, WOTS_ell)


def lwots_genpk(private_key: Tuple[bytes, ...]) -> bytes:
    tmp = []
    for key in private_key:
        tmp.append(wots_chain(key, WOTS_w - 1))
    return lwots_ltree(tmp)


def lwots_extract(sign: Tuple[bytes, ...], msg: bytes) -> bytes:
    tmp = []
    checksum = 0

    for i in range(0, WOTS_ell1, 2):
        v = msg[i // 2]
        a, b = (v >> 4) & 0xf, v & 0xf
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b)

        tmp.append(wots_chain(sign[i], WOTS_w - 1 - a))
        tmp.append(wots_chain(sign[i+1], WOTS_w - 1 - b))

    for i in range(WOTS_ell1, WOTS_ell):
        tmp.append(wots_chain(sign[i], WOTS_w - 1 - (checksum & 0xf)))
        checksum >>= 4

    return lwots_ltree(tmp)


def merkle_base_address(address: Address, base_address: Address=None) -> int:
    index = address.index & (MERKLE_hhh - 1)
    if base_address:
        base_address.layer = address.layer
        base_address.index = address.index - index
    return index


def merkle_compress_all(buf, height) -> bytes:
    for l in range(height):
        buf = [haraka512(buf[i] + buf[i + 1]) for i in range(0, len(buf), 2)]
    return buf[0]


def merkle_genpk(key: bytes, address: Address) -> bytes:
    base_address = Address()
    merkle_base_address(address, base_address)

    buf = []
    for j in range(MERKLE_hhh):
        wots_private_key = wots_gensk(key, base_address)
        wots_public_key = lwots_genpk(wots_private_key)
        buf.append(wots_public_key)

        base_address.index += 1

    # merkle tree
    public_key = merkle_compress_all(buf, MERKLE_h)
    return public_key


def merkle_extract(address: Address, sign: MerkleSignature, msg: bytes) -> bytes:
    index = merkle_base_address(address)
    wpk = lwots_extract(sign.wots_signature, msg)
    return merkle_compress_auth(wpk, index, sign.auth)


def merkle_sign(key, address: Address, msg: bytes) -> Tuple[bytes, MerkleSignature]:
    base_address = Address()
    index = merkle_base_address(address, base_address)

    buf = []
    wots_signature = None

    # leaves
    for j in range(MERKLE_hhh):
        wots_private_key = wots_gensk(key, base_address)
        wots_public_key = lwots_genpk(wots_private_key)
        buf.append(wots_public_key)

        base_address.index += 1
        if j == index:
            wots_signature = wots_sign(wots_private_key, msg)

    pk, auth = merkle_gen_auth(buf, MERKLE_h, index)
    signature = MerkleSignature(wots_signature, auth)
    return pk, signature


def merkle_gen_auth(buf: List[bytes], height: int, index: int) -> Tuple[bytes, Tuple[bytes, ...]]:
    auth = []

    for i in range(height):
        sibling = index ^ 1
        auth.append(buf[sibling])
        index >>= 1

        # compress pairs
        buf = [haraka512(buf[i] + buf[i+1]) for i in range(0, len(buf), 2)]

    public_key = buf[0]
    return public_key, tuple(auth)


def merkle_compress_auth(node: bytes, index: int, auth: Tuple[bytes, ...]) -> bytes:
    for i in range(len(auth)):
        if index % 2 == 0:
            buf = node + auth[i]
        else:
            buf = auth[i] + node
        node = haraka512(buf)
        index //= 2
    return node


def pors_gensk(key: bytes, address: Address) -> Tuple[bytes, ...]:
    counter = address.index.to_bytes(8, 'big') + address.layer.to_bytes(4, 'big') + b'\x00\x00\x00\x00'

    cipher = Cipher(algorithms.AES(key), modes.CTR(counter), backend=default_backend())
    encryptor = cipher.encryptor()

    pors_private_key = []
    for i in range(PORS_t):
        pors_private_key.append(encryptor.update(b'\x00' * HASH_SIZE))
    return tuple(pors_private_key)


def pors_sign(secret_key: Tuple[bytes, ...], subset: List[int]) -> Tuple[bytes, ...]:
    signature = []
    for i in range(PORS_k):
        index = subset[i]
        signature.append(secret_key[index])
    return tuple(signature)


def pors_randsubset(rand: bytes, msg: bytes) -> Tuple[int, Set[int]]:
    seed = haraka512(rand + msg)

    stream_len = 8 * PORS_k + HASH_SIZE
    cipher = Cipher(algorithms.AES(seed), modes.CTR(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    random_stream = encryptor.update(b'\x00' * stream_len) + encryptor.finalize()

    # compute address. can be simplified
    addr = 0
    for i in range(HASH_SIZE):
        addr = (addr << 8) | random_stream[i]
        addr &= GRAVITY_mask

    offset = HASH_SIZE
    subset = set()
    while len(subset) < PORS_k:
        index = int.from_bytes(random_stream[offset:offset + 4], 'big') % PORS_t
        offset += 4
        subset.add(index)
    return addr, subset


def merkle_gen_octopus(buf: List[bytes], height: int, indices: List[int], count: int) \
        -> Tuple[Tuple[bytes, ...], bytes]:
    octopus = []
    for l in range(height):
        i, j = 0, 0
        while i < count:
            index = indices[i]
            sibling = index ^ 1

            if i + 1 < count and indices[i + 1] == sibling:
                i += 1
            else:
                octopus.append(buf[sibling])
            indices[j] = indices[i] >> 1
            i += 1
            j += 1

        count = j
        buf = [haraka512(buf[i] + buf[i + 1]) for i in range(0, len(buf), 2)]
    root = buf[0]
    return tuple(octopus), root


def merkle_compress_octopus(nodes: List[bytes], height: int, octopus: Tuple[bytes, ...], octolen: int,
                            indices: List[int], count: int):
    offset = 0
    for l in range(height):
        i, j = 0, 0
        while i < count:
            index = indices[i]
            if index % 2 == 0:
                if i + 1 < count and indices[i + 1] == index + 1:
                    buf = nodes[i] + nodes[i + 1]
                    i += 1
                else:
                    assert offset < octolen
                    buf = nodes[i] + octopus[offset]
                    offset += 1

            else:
                assert offset < octolen
                buf = octopus[offset] + nodes[i]
                offset += 1

            nodes[j] = haraka512(buf)
            indices[j] = indices[i] >> 1
            j += 1
            i += 1
        count = j
    assert offset == octolen


def octoporst_sign(private_key: Tuple[bytes, ...], subset: Set[int]):
    sorted_subset = sorted(list(subset))
    s = pors_sign(private_key, sorted_subset)

    # leaves
    buf = [haraka256(key) for key in private_key]

    octopus, public_key = merkle_gen_octopus(buf, PORS_tau, sorted_subset, PORS_k)

    signature = OctoporstSignature(s, octopus, len(octopus))
    return signature, public_key


def octoporst_extract(sign: OctoporstSignature, subset: Set[int]) -> bytes:
    sorted_subset = sorted(list(subset))

    # compute leaves
    tmp = [haraka256(h) for h in sign.s]

    merkle_compress_octopus(tmp, PORS_tau, sign.octopus, sign.octolen, sorted_subset, PORS_k)
    return tmp[0]


def gravity_gen_secret_key(seed: bytes, salt: bytes) -> GravityPrivateKey:
    address = Address()
    n = GRAVITY_ccc

    # create sub merkle trees
    cache = []
    for i in range(n):
        address.index = i * MERKLE_hhh
        merkle_public_key = merkle_genpk(seed, address)
        cache.append(merkle_public_key)

    # cache layers of merkle trees
    for i in range(GRAVITY_c):
        cache = [haraka512(cache[i] + cache[i + 1]) for i in range(0, len(cache), 2)]
        n >>= 1
    return GravityPrivateKey(seed, salt, tuple(cache))


def gravity_gen_public_key(secret_key: GravityPrivateKey) -> bytes:
    return secret_key.cache[2 * GRAVITY_ccc - 2]


def gravity_sign(private_key: GravityPrivateKey, msg: bytes) -> GravitySignature:
    rand = haraka512(private_key.salt + msg)

    index, subset = pors_randsubset(rand, msg)
    address = Address(GRAVITY_d, index)

    pors_private_key = pors_gensk(private_key.seed, address)
    op_sign, public_key = octoporst_sign(pors_private_key, subset)

    h = public_key

    # hyper tree
    merkle_signature = []
    for layer in range(GRAVITY_d):
        address.layer -= 1
        h, sig = merkle_sign(private_key.seed, address, h)
        merkle_signature.append(sig)

        address.index >>= MERKLE_h
    return GravitySignature(rand, op_sign, tuple(merkle_signature))


def gravity_verify(public_key: bytes, signature: GravitySignature, msg: bytes) -> bool:
    addr, subset = pors_randsubset(signature.rand, msg)

    h = octoporst_extract(signature.op_sign, subset)

    address = Address(GRAVITY_d, addr)
    for layer in range(GRAVITY_d):
        address.layer -= 1
        pk = merkle_extract(address, signature.merkle[layer], h)
        h = pk
        address.index >>= MERKLE_h
    return h == public_key


def gravity_unserialize_signature(f) -> GravitySignature:
    # random data
    rand = f.read(32)

    # octoporst
    pors_signature = tuple([f.read(HASH_SIZE) for _ in range(PORS_k)])
    octopus = tuple([f.read(HASH_SIZE) for _ in range(512)])
    octopus_len = int.from_bytes(f.read(4), 'little')
    sign = OctoporstSignature(pors_signature, octopus, octopus_len)

    f.read(12)  # handle 16-bytes alignment

    # merkle
    merkle = []
    for i in range(GRAVITY_d):
        wots_signature = tuple([f.read(HASH_SIZE) for _ in range(WOTS_ell)])
        auth = tuple([f.read(HASH_SIZE) for _ in range(MERKLE_h)])
        merkle.append(MerkleSignature(wots_signature, auth))

    return GravitySignature(rand, sign, tuple(merkle))


def gravity_serialize_signature(f, signature: GravitySignature):
    # random data
    f.write(signature.rand)

    # octoporst
    op_sign = signature.op_sign
    for s in op_sign.s:
        f.write(s)
    for i in range(512):
        if i < op_sign.octolen:
            f.write(op_sign.octopus[i])
        else:
            f.write(b'\x00' * HASH_SIZE)
    f.write(op_sign.octolen.to_bytes(4, 'little'))
    f.write(b'\x00' * 12)  # alignment

    # merkle
    merkle = signature.merkle
    for i in range(GRAVITY_d):
        for s in merkle[i].wots_signature:
            f.write(s)
        for s in merkle[i].auth:
            f.write(s)

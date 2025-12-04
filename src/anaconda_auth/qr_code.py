"""QR code generator optimized for URLs.

Byte mode, EC-L, versions 1-6, fixed mask pattern.
Supports up to 134 character URLs.

Usage:
    from qr_url_encoder import generate_qr, qr_to_terminal
    print(qr_to_terminal("https://example.com"))
"""

# GF(2^8) arithmetic for Reed-Solomon
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    _GF_EXP[255:512] = _GF_EXP[0:257]


_init_gf()


def _gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            r[i + j] ^= _gf_mul(a, b)
    return r


def _gf_poly_div(dividend, divisor):
    r = list(dividend)
    for i in range(len(dividend) - len(divisor) + 1):
        if r[i]:
            for j in range(1, len(divisor)):
                if divisor[j]:
                    r[i + j] ^= _gf_mul(divisor[j], r[i])
    return r[-(len(divisor) - 1) :]


def _rs_encode(data, nsym):
    g = [1]
    for i in range(nsym):
        g = _gf_poly_mul(g, [1, _GF_EXP[i]])
    return _gf_poly_div(data + [0] * nsym, g)


# EC-L parameters: (total_cw, ec_per_block, num_blocks, data_cw_per_block)
EC_PARAMS = {
    1: (26, 7, 1, 19),
    2: (44, 10, 1, 34),
    3: (70, 15, 1, 55),
    4: (100, 20, 1, 80),
    5: (134, 26, 1, 108),
    6: (172, 18, 2, 68),
}

DATA_CAPACITY = {1: 17, 2: 32, 3: 53, 4: 78, 5: 106, 6: 134}

ALIGN_POSITIONS = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34]}


def select_version(data):
    """Select smallest version that fits the URL."""
    byte_len = len(data.encode("latin-1"))
    for v in range(1, 7):
        if DATA_CAPACITY[v] >= byte_len:
            return v
    raise ValueError(f"URL too long ({byte_len} bytes), max 134 chars")


def _encode_data(data, version):
    """Encode URL data into codewords with Reed-Solomon."""
    total, ec_per, nblocks, data_per = EC_PARAMS[version]
    data_cw = nblocks * data_per

    # Byte mode: 0100 + 8-bit length + data bytes
    bits = "0100" + format(len(data), "08b")
    for b in data.encode("latin-1"):
        bits += format(b, "08b")

    # Terminator + pad to byte boundary
    bits += "0" * min(4, data_cw * 8 - len(bits))
    if len(bits) % 8:
        bits += "0" * (8 - len(bits) % 8)

    # Convert to codewords and pad
    cw = [int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)]
    pad_idx = 0
    while len(cw) < data_cw:
        cw.append([236, 17][pad_idx % 2])
        pad_idx += 1

    # Split into blocks and add EC
    blocks = []
    for i in range(nblocks):
        block_data = cw[i * data_per : (i + 1) * data_per]
        blocks.append((block_data, _rs_encode(block_data, ec_per)))

    # Interleave data then EC
    result = []
    for i in range(data_per):
        for data_block, _ in blocks:
            if i < len(data_block):
                result.append(data_block[i])
    for i in range(ec_per):
        for _, ec_block in blocks:
            result.append(ec_block[i])

    return result


def create_matrix(version):
    """Create matrix with finder patterns, timing, alignment."""
    size = 17 + version * 4
    m = [[0] * size for _ in range(size)]
    f = [[False] * size for _ in range(size)]

    def set_fixed(r, c, val):
        if 0 <= r < size and 0 <= c < size:
            m[r][c] = val
            f[r][c] = True

    # Finder patterns
    for pr, pc in [(0, 0), (0, size - 7), (size - 7, 0)]:
        for r in range(7):
            for c in range(7):
                val = (
                    1
                    if (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                    else 0
                )
                set_fixed(pr + r, pc + c, val)

    # Separators
    for i in range(8):
        set_fixed(7, i, 0)
        set_fixed(i, 7, 0)
        set_fixed(7, size - 8 + i, 0)
        set_fixed(i, size - 8, 0)
        set_fixed(size - 8, i, 0)
        set_fixed(size - 8 + i, 7, 0)

    # Timing patterns
    for i in range(8, size - 8):
        set_fixed(6, i, i % 2 == 0)
        set_fixed(i, 6, i % 2 == 0)

    # Dark module
    set_fixed(size - 8, 8, 1)

    # Alignment pattern (v2-6 have exactly one at intersection of two positions)
    positions = ALIGN_POSITIONS[version]
    if len(positions) == 2:
        ar, ac = positions[1], positions[1]  # Bottom-right position
        for dr in range(-2, 3):
            for dc in range(-2, 3):
                val = (
                    1
                    if (dr in (-2, 2) or dc in (-2, 2) or (dr == 0 and dc == 0))
                    else 0
                )
                set_fixed(ar + dr, ac + dc, val)

    # Reserve format info areas
    for i in range(9):
        f[8][i] = True
        f[i][8] = True
    for i in range(7):
        f[size - 1 - i][8] = True
    for i in range(8):
        f[8][size - 8 + i] = True

    return m, f


def place_data(matrix, fixed, codewords):
    """Place data codewords in zigzag pattern."""
    size = len(matrix)
    bits = "".join(format(cw, "08b") for cw in codewords)
    bit_idx = 0
    col = size - 1
    going_up = True

    while col >= 0 and bit_idx < len(bits):
        if col == 6:
            col -= 1
            continue

        for row_iter in range(size):
            row = (size - 1 - row_iter) if going_up else row_iter
            for dc in [0, -1]:
                c = col + dc
                if 0 <= c < size and not fixed[row][c] and bit_idx < len(bits):
                    matrix[row][c] = int(bits[bit_idx])
                    bit_idx += 1

        col -= 2
        going_up = not going_up


def apply_mask(matrix, fixed):
    """Apply mask pattern 0: (row + col) % 2 == 0."""
    size = len(matrix)
    for r in range(size):
        for c in range(size):
            if not fixed[r][c] and (r + c) % 2 == 0:
                matrix[r][c] ^= 1


def place_format_info(matrix):
    """Place format information."""
    size = len(matrix)

    # Precomputed format info bits for EC-L + mask 0 (bit 14 to bit 0)
    bits = [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0]

    # Copy 1: around top-left finder
    copy1_pos = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ]
    for i, (r, c) in enumerate(copy1_pos):
        matrix[r][c] = bits[i]

    # Copy 2: bottom-left column and top-right row
    for i in range(7):
        matrix[size - 1 - i][8] = bits[i]
    for i in range(8):
        matrix[8][size - 8 + i] = bits[7 + i]


def generate_qr(url):
    """Generate QR code matrix for URL.

    Returns:
        Matrix as list of lists (1=dark, 0=light)
    """
    version = select_version(url)
    codewords = _encode_data(url, version)
    m, f = create_matrix(version)
    place_data(m, f, codewords)
    apply_mask(m, f)
    place_format_info(m)
    return m


def qr_to_terminal(url, quiet_zone=4, invert=False):
    """Generate terminal-printable QR code."""
    matrix = generate_qr(url)
    size = len(matrix)

    full_size = size + 2 * quiet_zone
    full = [[0] * full_size for _ in range(full_size)]
    for r in range(size):
        for c in range(size):
            full[r + quiet_zone][c + quiet_zone] = matrix[r][c]

    BOTH_DARK, TOP_DARK, BOT_DARK, BOTH_LIGHT = "█", "▀", "▄", " "
    if invert:
        BOTH_DARK, BOTH_LIGHT = BOTH_LIGHT, BOTH_DARK
        TOP_DARK, BOT_DARK = BOT_DARK, TOP_DARK

    lines = []
    for r in range(0, full_size, 2):
        line = ""
        for c in range(full_size):
            top = full[r][c] if r < full_size else 0
            bot = full[r + 1][c] if r + 1 < full_size else 0
            line += (
                BOTH_DARK
                if top and bot
                else TOP_DARK
                if top
                else BOT_DARK
                if bot
                else BOTH_LIGHT
            )
        lines.append(line)

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "https://anaconda.com"
    print(qr_to_terminal(url))
    print(f"\nURL: {url}")
    print(f"Length: {len(url)} chars, Version: {select_version(url)}")

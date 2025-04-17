def load_variables(filename="out.out"):
    with open(filename, "r") as f:
        content = f.read()
        marker = "matrix_a"
        marker_index = content.find(marker)
        if marker_index == -1:
            raise ValueError("matrix_a not found in output – did the test run finish?")
        content = content[marker_index:]

    env = {}
    exec(content, {}, env)
    return env


vars_loaded = load_variables("out.out")

matrix_a = vars_loaded["matrix_a"]
input_1 = vars_loaded["input_1"]
input_2 = vars_loaded["input_2"]
input_3 = vars_loaded["input_3"]
image_bits_after_compress_1 = vars_loaded["image_bits_after_compress_1"]
cutoff_after_compress_1 = vars_loaded["cutoff_after_compress_1"]
image_bits_after_compress_2 = vars_loaded["image_bits_after_compress_2"]
cutoff_after_compress_2 = vars_loaded["cutoff_after_compress_2"]
image_bits_after_mix_1 = vars_loaded["image_bits_after_mix_1"]
cutoff_after_mix_1 = vars_loaded["cutoff_after_mix_1"]
image_bits_after_mix_2 = vars_loaded["image_bits_after_mix_2"]
cutoff_after_mix_2 = vars_loaded["cutoff_after_mix_2"]
image_bits_after_mix_3 = vars_loaded["image_bits_after_mix_3"]
cutoff_after_mix_3 = vars_loaded["cutoff_after_mix_3"]
squeeze_output_1 = vars_loaded["squeeze_output_1"]
cutoff_after_squeeze_1 = vars_loaded["cutoff_after_squeeze_1"]
squeeze_output_2 = vars_loaded["squeeze_output_2"]
cutoff_after_squeeze_2 = vars_loaded["cutoff_after_squeeze_2"]
squeeze_output_3 = vars_loaded["squeeze_output_3"]
cutoff_after_squeeze_3 = vars_loaded["cutoff_after_squeeze_3"]
pipeline_time_ns = vars_loaded.get("pipeline_time_ns", None)

DEGREE = 512
BASE_256 = 256
BASE_257 = 257
SQUEEZE_INPUT_LAYERS = 2

stage1_inputs = len(input_1) + len(input_2)
print(
    "Config:",
    f"DEGREE={DEGREE},",
    f"base_256={BASE_256},",
    f"base_257={BASE_257},",
    f"squeeze_inputs={SQUEEZE_INPUT_LAYERS},",
    "matrix_a_range=[-128,127]"
)
print(f"Loaded {len(matrix_a)} matrix rows and {stage1_inputs} input polynomials for compress stage 1.")
print(
    f"Image bits layers after compress: stage1={len(image_bits_after_compress_1)}, "
    f"stage2={len(image_bits_after_compress_2)}, polynomial degree: {DEGREE}"
)

P.<X> = PolynomialRing(ZZ)
R.<x> = P.quotient(X^DEGREE + 1)


def list_to_poly(coeffs):
    if len(coeffs) > DEGREE:
        raise ValueError("Coefficient list is longer than the ring degree.")
    return sum(ZZ(c) * x**i for i, c in enumerate(coeffs))


def compose_image(bit_layers):
    if not bit_layers:
        raise ValueError("No bit layers provided for image reconstruction.")
    layer_len = len(bit_layers[0])
    composed = [0] * layer_len
    for bit_idx, layer in enumerate(bit_layers):
        if len(layer) != layer_len:
            raise ValueError("Inconsistent bit layer lengths.")
        for i, bit in enumerate(layer):
            if bit not in (0, 1):
                raise ValueError("Image bits must be either 0 or 1.")
            composed[i] += (bit << bit_idx)
    return composed


def compose_image_balanced(bit_layers):
    """Compose using balanced binary weights (1, -2, 4, 8, 16, 32, 64, 128)."""
    weights = [1, -2, 4, 8, 16, 32, 64, 128]
    if len(bit_layers) != len(weights):
        raise ValueError(f"Expected 8 bit layers for balanced compose, got {len(bit_layers)}.")
    layer_len = len(bit_layers[0])
    composed = [0] * layer_len
    for bit_idx, layer in enumerate(bit_layers):
        for i, bit in enumerate(layer):
            composed[i] += bit * weights[bit_idx]
    return composed


if len(matrix_a) != stage1_inputs:
    raise ValueError("Matrix rows and input vectors mismatch for compress stage 1.")

matrix_polys = [list_to_poly(row) for row in matrix_a]

def verify_compress(name, left_vectors, right_vectors, bit_layers, cutoff_vals):
    if len(matrix_polys) != len(left_vectors) + len(right_vectors):
        raise ValueError(f"{name}: matrix/input length mismatch ({len(left_vectors) + len(right_vectors)} vs {len(matrix_polys)}).")
    inputs = left_vectors + right_vectors
    input_polys_local = [list_to_poly(inp) for inp in inputs]
    cutoff_poly_local = list_to_poly(cutoff_vals)
    image_coeffs_local = compose_image(bit_layers)
    image_poly_local = list_to_poly(image_coeffs_local)
    lhs_local = sum((m * inp for m, inp in zip(matrix_polys, input_polys_local)), R.zero())
    rhs_local = image_poly_local + BASE_256 * cutoff_poly_local
    if lhs_local == rhs_local:
        print(f"{name}: verification passed.")
    else:
        diff_poly_local = (lhs_local - rhs_local).lift()
        diffs_local = [(i, coeff) for i, coeff in enumerate(diff_poly_local.list()) if coeff != 0]
        print(f"{name}: verification FAILED.")
        print(f"Found {len(diffs_local)} mismatching coefficients; first few: {diffs_local[:10]}")


verify_compress("compress_stage_1", input_1, input_2, image_bits_after_compress_1, cutoff_after_compress_1)
verify_compress("compress_stage_2", image_bits_after_compress_1, input_3, image_bits_after_compress_2, cutoff_after_compress_2)

mix_matrix_polys = matrix_polys[:8]


def verify_mix(name, input_vectors, bit_layers, cutoff_vals, base):
    # if len(input_vectors) != len(mix_matrix_polys):
    #    raise ValueError(f"{name}: expected {len(mix_matrix_polys)} input polynomials.")
    input_polys_local = [list_to_poly(inp) for inp in input_vectors]
    cutoff_poly_local = list_to_poly(cutoff_vals)
    image_coeffs_local = compose_image(bit_layers)
    image_poly_local = list_to_poly(image_coeffs_local)
    lhs_local = sum((m * inp for m, inp in zip(mix_matrix_polys, input_polys_local)), R.zero())
    rhs_local = image_poly_local + base * cutoff_poly_local
    if lhs_local == rhs_local:
        print(f"{name}: verification passed (base {base}).")
    else:
        diff_poly_local = (lhs_local - rhs_local).lift()
        diffs_local = [(i, coeff) for i, coeff in enumerate(diff_poly_local.list()) if coeff != 0]
        print(f"{name}: verification FAILED.")
        print(f"Found {len(diffs_local)} mismatching coefficients; first few: {diffs_local[:10]}")


verify_mix("mix_257_stage_1", image_bits_after_compress_2, image_bits_after_mix_1, cutoff_after_mix_1, BASE_257)
# mix_256 is currently disabled in test.c, so skip its verification.
# verify_mix("mix_256_stage_2", image_bits_after_compress_2, image_bits_after_mix_2, cutoff_after_mix_2, BASE_256)
verify_mix("mix_257_stage_3", image_bits_after_mix_2, image_bits_after_mix_3, cutoff_after_mix_3, BASE_257)


def verify_squeeze(name, input_bit_layers, output_bit_layers, cutoff_vals):
    if len(input_bit_layers) < SQUEEZE_INPUT_LAYERS:
        raise ValueError(f"{name}: squeeze expects at least {SQUEEZE_INPUT_LAYERS} input layers.")
    input_polys = [list_to_poly(input_bit_layers[i]) for i in range(SQUEEZE_INPUT_LAYERS)]
    cutoff_poly_local = list_to_poly(cutoff_vals)
    image_coeffs_local = compose_image_balanced(output_bit_layers)
    image_poly_local = list_to_poly(image_coeffs_local)
    lhs_local = matrix_polys[0] * input_polys[0] + matrix_polys[1] * input_polys[1]
    rhs_local = image_poly_local + BASE_256 * cutoff_poly_local
    if lhs_local == rhs_local:
        print(f"{name}: verification passed (base 256, balanced binary, 2 input layers).")
    else:
        diff_poly_local = (lhs_local - rhs_local).lift()
        diffs_local = [(i, coeff) for i, coeff in enumerate(diff_poly_local.list()) if coeff != 0]
        print(f"{name}: verification FAILED.")
        print(f"Found {len(diffs_local)} mismatching coefficients; first few: {diffs_local[:10]}")


verify_squeeze("squeeze_stage_1", image_bits_after_mix_3, squeeze_output_1, cutoff_after_squeeze_1)
verify_squeeze("squeeze_stage_2", squeeze_output_1, squeeze_output_2, cutoff_after_squeeze_2)
verify_squeeze("squeeze_stage_3", squeeze_output_2, squeeze_output_3, cutoff_after_squeeze_3)

if pipeline_time_ns is not None:
    print("Pipeline time (ns):", pipeline_time_ns)

#include <stdint.h>
#include <cstddef>
#include <hexl/hexl.hpp>
#include <unordered_map>
#include <memory>
#include <utility>
#include <immintrin.h>

class NTTCache {
public:
    static intel::hexl::NTT& Get(size_t n, uint64_t modulus) {
        auto key = std::make_pair(n, modulus);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            // Construct and insert
            it = cache_.emplace(key, std::make_unique<intel::hexl::NTT>(n, modulus)).first;
        }
        return *(it->second);
    }

private:
    // Hash for std::pair
    struct pair_hash {
        std::size_t operator()(const std::pair<size_t, uint64_t>& p) const {
            return std::hash<size_t>()(p.first) ^ (std::hash<uint64_t>()(p.second) << 1);
        }
    };

    static inline std::unordered_map<std::pair<size_t, uint64_t>, std::unique_ptr<intel::hexl::NTT>, pair_hash> cache_;
};

extern "C" __attribute__((externally_visible)) uint64_t multiply_mod(uint64_t a, uint64_t b, uint64_t modulus) {
    return intel::hexl::MultiplyMod(a, b, modulus);
}

extern "C" __attribute__((externally_visible)) 
    uint64_t add_mod(uint64_t a, uint64_t b, uint64_t modulus) {
        return intel::hexl::AddUIntMod(a, b, modulus);
}

extern "C" __attribute__((externally_visible)) uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t modulus) {
    return intel::hexl::SubUIntMod(a, b, modulus);
}

extern "C" __attribute__((externally_visible)) const uint64_t* get_roots(size_t n, uint64_t modulus) {
    auto& ntt = NTTCache::Get(n, modulus);
    return ntt.GetRootOfUnityPowers().data(); 
}

extern "C" __attribute__((externally_visible)) const uint64_t inv_mod(uint64_t a, uint64_t modulus) {
    return intel::hexl::InverseMod(a, modulus);
}

extern "C" __attribute__((externally_visible)) const uint64_t* get_inv_roots(size_t n, uint64_t modulus) {
    auto& ntt = NTTCache::Get(n, modulus);
    return ntt.GetInvRootOfUnityPowers().data(); 
}

extern "C" __attribute__((externally_visible)) uint64_t power_mod(uint64_t a, uint64_t b, uint64_t modulus) {
    return intel::hexl::PowMod(a, b, modulus);
}

extern "C" __attribute__((externally_visible)) void eltwise_mult_mod(uint64_t* result, const uint64_t* operand1, const uint64_t* operand2, uint64_t n, uint64_t modulus) {
    intel::hexl::EltwiseMultMod(result, operand1, operand2, n, modulus, 1);
}
extern "C" __attribute__((externally_visible)) void eltwise_fma_mod(uint64_t* result, const uint64_t* operand1, const uint64_t operand2, const uint64_t* operand3, uint64_t n, uint64_t modulus) {
    intel::hexl::EltwiseFMAMod(result, operand1, operand2, operand3, n, modulus, 1);
}


extern "C" __attribute__((externally_visible)) void multiply_poly(uint64_t* result, const uint64_t* operand1, const uint64_t* operand2, uint64_t n, uint64_t modulus) {
    // Step 1: Perform forward NTT on both polynomials
    std::vector<uint64_t> op1(operand1, operand1 + n);
    std::vector<uint64_t> op2(operand2, operand2 + n);
    std::vector<uint64_t> ntt_result1(n);
    std::vector<uint64_t> ntt_result2(n);
    auto& ntt = NTTCache::Get(n, modulus);

    ntt.ComputeForward(ntt_result1.data(), op1.data(), 1, 1);
    ntt.ComputeForward(ntt_result2.data(), op2.data(), 1, 1);

    // Step 2: Multiply the transformed polynomials element-wise
    std::vector<uint64_t> ntt_product(n);
    intel::hexl::EltwiseMultMod(ntt_product.data(), ntt_result1.data(), ntt_result2.data(), n, modulus, 1);

    // Step 3: Perform the inverse NTT on the product
    ntt.ComputeInverse(result, ntt_product.data(), 1, 1);
    intel::hexl::EltwiseReduceMod(result, result, n, modulus, 1, 4);


}

extern "C" __attribute__((externally_visible)) void polynomial_multiply_cyclotomic_mod(
    uint64_t* result,
    const uint64_t* operand1,
    const uint64_t* operand2,
    size_t phi,
    uint64_t mod_q
) {
    std::vector<uint64_t> temp_result(2 * phi - 1, 0);

    multiply_poly(temp_result.data(), operand1, operand2, phi, mod_q);

    // Apply the cyclotomic polynomial reduction using HEXL
    for (size_t i = phi; i < temp_result.size(); ++i) {
        temp_result[i - phi] = (temp_result[i - phi] + temp_result[i]) % mod_q;
    }

    // Set the reduced result and finalize reduction using HEXL
    for (size_t i = 0; i < phi; ++i) {
        temp_result[i] = ((mod_q) + temp_result[i] - temp_result[phi]) % (mod_q);
    }

    intel::hexl::EltwiseReduceMod(result, temp_result.data(), phi, mod_q, 4, 1);
}

extern "C" __attribute__((externally_visible)) void eltwise_reduce_mod(
    uint64_t* result,
    const uint64_t* operand,
    size_t n,
    uint64_t modulus
) {
    intel::hexl::EltwiseReduceMod(result, operand, n, modulus, modulus, 1);
}


// extern "C" __attribute__((externally_visible)) void eltwise_reduce_mod_naive(
//     uint64_t* result,
//     const uint64_t* operand,
//     size_t n,
//     uint64_t modulus
// ) {
//     size_t i = 0;
//     __m512i v_modulus = _mm512_set1_epi64(modulus);
//     for (; i + 8 <= n; i += 8) {
//         __m512i v_operand = _mm512_loadu_si512((const __m512i*)(operand + i));
//         __m512i v_result = _mm512_rem_epi64(v_operand, v_modulus);
//         _mm512_storeu_si512((__m512i*)(result + i), v_result);
//     }
//     for (; i < n; ++i) {
//         result[i] = operand[i] % modulus;
//     }
// }

// extern "C" __attribute__((externally_visible)) void eltwise_reduce_mod_naive(
//     uint64_t* result,
//     const uint64_t* operand,
//     size_t n,
//     uint64_t modulus
// ) {
//     for (size_t i = 0; i < n; ++i) {
//         result[i] = operand[i] % modulus;
//     }
// }

extern "C" __attribute__((externally_visible)) void eltwise_add_mod(
    uint64_t* result,
    const uint64_t* operand1,
    const uint64_t* operand2,
    size_t n,
    uint64_t modulus
) {
    intel::hexl::EltwiseAddMod(result, operand1, operand2, n, modulus);
}


extern "C" __attribute__((externally_visible)) void eltwise_sub_mod(
    uint64_t* result,
    const uint64_t* operand1,
    const uint64_t* operand2,
    size_t n,
    uint64_t modulus
) {
    intel::hexl::EltwiseSubMod(result, operand1, operand2, n, modulus);
}


#include <vector>
#include <hexl/ntt/ntt.hpp>

extern "C" __attribute__((externally_visible)) void ntt_forward_in_place(
    uint64_t* operand,
    size_t n,
    uint64_t modulus
) {
    auto& ntt = NTTCache::Get(n, modulus);
    ntt.ComputeForward(operand, operand, 1, 1);
}

extern "C" __attribute__((externally_visible)) void ntt_inverse_in_place(
    uint64_t* operand,
    size_t n,
    uint64_t modulus
) {
    auto& ntt = NTTCache::Get(n, modulus);
    ntt.ComputeInverse(operand, operand, 1, 1);
}

extern "C" __attribute__((externally_visible)) void ntt_forward(
    uint64_t* operand1,
    uint64_t* operand2,
    size_t n,
    uint64_t modulus
) {
    auto& ntt = NTTCache::Get(n, modulus);
    ntt.ComputeForward(operand1, operand2, 1, 1);
}

extern "C" __attribute__((externally_visible)) void ntt_inverse(
    uint64_t* operand1,
    uint64_t* operand2,
    size_t n,
    uint64_t modulus
) {
    auto& ntt = NTTCache::Get(n, modulus);
    ntt.ComputeInverse(operand1, operand2, 1, 1);
}


extern "C" __attribute__((externally_visible)) const uint64_t sum(const uint64_t* operand1, uint64_t n, uint64_t modulus) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < n; ++i) {
        sum = intel::hexl::AddUIntMod(sum, operand1[i], modulus);
    }
    return sum;
}

extern "C" __attribute__((externally_visible)) const uint64_t sum_fast(const uint64_t* operand1, uint64_t n, uint64_t modulus) {
    // Use a reduction tree with eltwise_add_mod until n < 16, then use sum
    std::vector<uint64_t> buffer;
    buffer.reserve(n);
    // assume n is power-of-two
    size_t new_n = (n + 1) / 2;

    eltwise_add_mod(buffer.data(), operand1, operand1 + new_n, new_n, modulus);


    n = new_n;

    std::vector<uint64_t> buffer2;
    while (n >= 16) {
        size_t new_n = (n + 1) / 2;
        eltwise_add_mod(buffer.data(), buffer.data(), buffer.data() + new_n, new_n, modulus);

        n = new_n;
    }
    // Now n < 16, use the sum function
    return sum(buffer.data(), n, modulus);
}

extern "C" __attribute__((externally_visible)) const uint64_t sum_sq(const uint64_t* operand1, uint64_t n, uint64_t modulus) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < n; ++i) {
        sum = intel::hexl::AddUIntMod(sum, intel::hexl::MultiplyMod(operand1[i], operand1[i], modulus), modulus);
    }
    return sum;
}


extern "C" __attribute__((externally_visible)) const uint64_t sum_sq_fast(const uint64_t* operand1, uint64_t n, uint64_t modulus) {
    std::vector<uint64_t> squares(n);
    intel::hexl::EltwiseMultMod(squares.data(), operand1, operand1, n, modulus, 1);
    uint64_t sum = sum_fast(squares.data(), n, modulus);
    return sum;
}

#include "../include/clwe/ntt_engine.hpp"
#include "../include/clwe/cpu_features.hpp"
#include <iostream>
#include <chrono>
#include <random>
#include <vector>
#include <iomanip>

using namespace clwe;
using namespace std::chrono;

void generate_random_polynomial(uint32_t* poly, size_t size, uint32_t modulus) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, modulus - 1);
    
    for (size_t i = 0; i < size; ++i) {
        poly[i] = dis(gen);
    }
}

double benchmark_single_multiply(NTTEngine& engine, const uint32_t* a, const uint32_t* b, uint32_t* result, size_t iterations) {
    auto start = high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        engine.multiply(a, b, result);
    }
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<nanoseconds>(end - start).count();
    
    return static_cast<double>(duration) / iterations;
}

double benchmark_batch_multiply(NTTEngine& engine, std::vector<std::vector<uint32_t>>& a_batch,
                               std::vector<std::vector<uint32_t>>& b_batch,
                               std::vector<std::vector<uint32_t>>& result_batch, size_t iterations) {
    auto start = high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        std::vector<const uint32_t*> a_ptrs(a_batch.size());
        std::vector<const uint32_t*> b_ptrs(b_batch.size());
        std::vector<uint32_t*> result_ptrs(result_batch.size());
        
        for (size_t j = 0; j < a_batch.size(); ++j) {
            a_ptrs[j] = a_batch[j].data();
            b_ptrs[j] = b_batch[j].data();
            result_ptrs[j] = result_batch[j].data();
        }
        
        engine.batch_multiply(a_ptrs.data(), b_ptrs.data(), result_ptrs.data(), a_batch.size());
    }
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<nanoseconds>(end - start).count();
    
    return static_cast<double>(duration) / iterations;
}

int main() {
    std::cout << "=== ColorSign SIMD Optimization Benchmark ===" << std::endl;
    
    CPUFeatures features = CPUFeatureDetector::detect();
    std::cout << "CPU Features: " << features.to_string() << std::endl;
    std::cout << "Max SIMD Support: ";
    switch (features.max_simd_support) {
        case SIMDSupport::AVX512: std::cout << "AVX-512"; break;
        case SIMDSupport::AVX2: std::cout << "AVX2"; break;
        case SIMDSupport::NEON: std::cout << "NEON"; break;
        default: std::cout << "None"; break;
    }
    std::cout << std::endl << std::endl;
    
    const uint32_t q = 8380417;
    const uint32_t n = 256;
    const size_t iterations = 1000;
    
    std::vector<SIMDSupport> support_levels = {
        SIMDSupport::NONE,
        SIMDSupport::AVX2,
        SIMDSupport::AVX512
    };
    
    for (auto simd_support : support_levels) {
        try {
            std::cout << "Testing " << (simd_support == SIMDSupport::NONE ? "Scalar" :
                      simd_support == SIMDSupport::AVX2 ? "AVX2" : "AVX-512") 
                      << " implementation..." << std::endl;
            
            auto engine = create_ntt_engine(simd_support, q, n);
            
            if (engine->get_simd_support() != simd_support && simd_support != SIMDSupport::NONE) {
                std::cout << "  Warning: Engine created with " << static_cast<int>(engine->get_simd_support())
                         << " instead of " << static_cast<int>(simd_support) << std::endl;
            }
            
            std::cout << "  Actual SIMD Support: " << static_cast<int>(engine->get_simd_support()) << std::endl;
            std::cout << "  Cache Optimal: " << (engine->is_cache_optimal() ? "Yes" : "No") << std::endl;
            
            std::vector<uint32_t> a(n), b(n), result(n);
            generate_random_polynomial(a.data(), n, q);
            generate_random_polynomial(b.data(), n, q);
            
            double single_time = benchmark_single_multiply(*engine, a.data(), b.data(), result.data(), iterations);
            std::cout << "  Single multiply: " << std::fixed << std::setprecision(2) 
                     << single_time << " ns" << std::endl;
            
            if (engine->get_simd_support() != SIMDSupport::NONE) {
                const size_t batch_size = 8;
                std::vector<std::vector<uint32_t>> a_batch(batch_size, std::vector<uint32_t>(n));
                std::vector<std::vector<uint32_t>> b_batch(batch_size, std::vector<uint32_t>(n));
                std::vector<std::vector<uint32_t>> result_batch(batch_size, std::vector<uint32_t>(n));
                
                for (size_t i = 0; i < batch_size; ++i) {
                    generate_random_polynomial(a_batch[i].data(), n, q);
                    generate_random_polynomial(b_batch[i].data(), n, q);
                }
                
                double batch_time = benchmark_batch_multiply(*engine, a_batch, b_batch, result_batch, iterations / 10);
                std::cout << "  Batch multiply (" << batch_size << "): " << std::fixed << std::setprecision(2) 
                         << batch_time << " ns" << std::endl;
                
                double expected_speedup = (simd_support == SIMDSupport::AVX2) ? 5.0 : 8.0;
                if (batch_time < single_time / expected_speedup * 1.5) {
                    std::cout << "  ✓ Significant speedup detected!" << std::endl;
                } else {
                    std::cout << "  ⚠ Expected speedup not achieved" << std::endl;
                }
            }
            
            std::cout << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "  Error: " << e.what() << std::endl << std::endl;
        }
    }
    
    std::cout << "Benchmark completed!" << std::endl;
    return 0;
}
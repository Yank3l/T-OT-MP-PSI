#pragma once

#include "Crypto/PRNG.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>

__uint128_t ZZ_to_ui128(const NTL::ZZ& zz_value);
std::vector<NTL::ZZ_p> ShareSecret(const NTL::ZZ_p secret,u64 numShares, u64 threshold, NTL::ZZ p);
std::vector<NTL::ZZ_p> GenerateUpdateValues(u64 numShares, u64 threshold, NTL::ZZ p);
NTL::ZZ lagrange_interpolation(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& shares, NTL::ZZ mod);
int reconstruct_secret(const std::vector<int>& selected_indices, const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& all_shares, const NTL::ZZ p, const NTL::ZZ secret); 
void get_combinations_iterative(int totalNumShares, int threshold, std::vector<std::vector<int>>& all_combinations);

void tparty(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials);

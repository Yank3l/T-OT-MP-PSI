#include "Network/BtEndpoint.h" 

#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "Common/Defines.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <numeric>
#include <iostream>
#include <unordered_set>
#include <boost/multiprecision/cpp_int.hpp>
#include <bitset>
#include <dirent.h>


using uint256_t = boost::multiprecision::uint256_t;
//#define OOS
//#define PRINT
#define pows  { 16/*8,12,,20*/ }
#define threadss {1/*1,4,16,64*/}
#define  numTrial 2

// OT-MP-PSI


struct Uint128Hash {
    std::size_t operator()(const __uint128_t& key) const {
        return std::hash<uint64_t>()(static_cast<uint64_t>(key >> 64)) ^ std::hash<uint64_t>()(static_cast<uint64_t>(key));
    }
};


struct Uint128Equal {
    bool operator()(const __uint128_t& a, const __uint128_t& b) const {
        return a == b;
    }
};

__uint128_t ZZ_to_ui128(const NTL::ZZ& zz_value) 
{
    uint8_t bytes[16] = {0};
    NTL::BytesFromZZ(bytes, zz_value, 16);

    __uint128_t result = 0;
    for (int i = 0; i < 16; i++) {
        result |= (__uint128_t)bytes[i] << (8 * i);
    }
    return result;
}




std::vector<NTL::ZZ_p> ShareSecret(const NTL::ZZ_p secret,u64 numShares, u64 threshold, NTL::ZZ p)
{
   
    std::vector<NTL::ZZ_p> shares(numShares);
    
    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, NTL::conv<NTL::ZZ_p>(secret));
    for (long i = 1; i < threshold; i++)
    {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, p);
        NTL::SetCoeff(poly, i, NTL::conv<NTL::ZZ_p>(coef)); 
    }

  	for (long i = 0; i < numShares; i++)
    {
        shares[i] = NTL::eval(poly, NTL::to_ZZ_p(i+1)); 
    }
    return shares;
}


std::vector<NTL::ZZ_p> GenerateUpdateValues(u64 numShares, u64 threshold, NTL::ZZ p)
{

    std::vector<NTL::ZZ_p> updates_values;
    updates_values.resize(numShares);
    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, 0);
    for (int j = 1; j < threshold; j++)
    {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, p);
        NTL::SetCoeff(poly, j, NTL::conv<NTL::ZZ_p>(coef)); 
    }
        
     for (int j = 0; j < numShares; j++)
    {
        updates_values[j] = NTL::eval(poly, NTL::to_ZZ_p(j+1)); 
    }
      
    return updates_values;
}


NTL::ZZ lagrange_interpolation(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& shares, NTL::ZZ mod) 
{
    NTL::ZZ secret = NTL::conv<NTL::ZZ>("0");
    int t = shares.size();
	std::vector<NTL::ZZ> inverses(t, NTL::conv<NTL::ZZ>(1));
	std::vector<NTL::ZZ> neg_xj(t);

	//-xj % mod
	for (int j = 0; j < t; ++j) {
		neg_xj[j] = SubMod(mod, shares[j].first, mod);
    }

    // inver
    for (int i = 0; i < t; ++i) {
		NTL::ZZ denominator = NTL::conv<NTL::ZZ>(1);
        for (int j = 0; j < t; ++j) {
            if (i != j) {
                NTL::ZZ diff = SubMod(shares[i].first, shares[j].first, mod);
                denominator = MulMod(denominator, diff, mod);
            }
        }
        inverses[i] = InvMod(denominator, mod);  
    }


    for (int i = 0; i < t; ++i) {
        NTL::ZZ li = inverses[i]; 
        for (int j = 0; j < t; ++j) {
            if (i != j) {
                li = MulMod(li, neg_xj[j], mod);
            }
        }
        secret = AddMod(secret, MulMod(shares[i].second, li, mod), mod);
    }
    return secret; 
}

int reconstruct_secret(const std::vector<int>& selected_indices, const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& all_shares, 
	const NTL::ZZ p, const NTL::ZZ secret) 
{
	std::vector<std::pair<NTL::ZZ, NTL::ZZ>> selected_shares;
	selected_shares.reserve(selected_indices.size());
	for (int index : selected_indices) 
	{
        selected_shares.push_back(all_shares[index]);
    }

	NTL::ZZ res = lagrange_interpolation(selected_shares, p);

	return res == secret;
}


void get_combinations_iterative(int totalNumShares, int threshold, std::vector<std::vector<int>>& all_combinations) 
{
    std::vector<int> current_combination;
    std::vector<int> indices(threshold); 

    for (int i = 0; i < threshold; ++i) 
	{
        indices[i] = i; 
    }

    while (true) 
	{
        
        current_combination.clear();
        for (int i = 0; i < threshold; ++i) 
		{
            current_combination.push_back(indices[i]);
        }
        all_combinations.push_back(current_combination);

        
        int i = threshold - 1;
        while (i >= 0 && indices[i] == totalNumShares - threshold + i) 
		{
            --i;
        }
        if (i < 0)
		{
            break; 
        }
        ++indices[i];
        for (int j = i + 1; j < threshold; ++j) 
		{
            indices[j] = indices[j - 1] + 1; 
        }
    }
}

template<typename T>
void deep_clear(std::vector<std::vector<T>>& vecvec) {
    for (auto& v : vecvec) std::vector<T>().swap(v);
    std::vector<std::vector<T>>().swap(vecvec);
}

template<typename T>
void release_vector(std::vector<T>& v) {
    std::vector<T>().swap(v);
}


//leader is n-1
void tparty(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials)
{
	u64 opt = 0;
	std::fstream runtime;
	u64 leaderIdx = nParties - 1; //leader party
	std::vector<u64> mIntersection;
	if (myIdx == 0)
		runtime.open("./runtime_client.txt", runtime.app | runtime.out);

	if (myIdx == leaderIdx)
		runtime.open("./runtime_leader.txt", runtime.app | runtime.out);	
#pragma region setup

	double totalTime = 0, totalAvgTime = 0, totalShareTime = 0, totalAvgShareTime = 0, totalReconTime = 0, totalAvgReconTime = 0;
	
	std::vector<double> eachTime(nTrials), eachShareTime(nTrials), eachReconTime(nTrials);
	double total_sd = 0, total_share_sd = 0, total_recon_sd = 0;

	u64 totalNumShares = nParties;

	u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

	std::string name("psi");
	BtIOService ios(0);

	std::vector<BtEndpoint> ep(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}
	

	std::vector<std::vector<Channel*>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				//chls[i][j].mEndpoint;
			}
		}
	}
#pragma endregion



	u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
	


	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
		u64 expected_intersection;
		Timer timer;
		mIntersection.clear();

#pragma region input


		NTL::ZZ p, intersection;
		NTL::ZZ seed_p = NTL::conv<NTL::ZZ>("2412184378664027336206160438520832671112");
    	NTL::SetSeed(seed_p);
		p = NTL::conv<NTL::ZZ>("340282366920938463463374607431768211297");  
		NTL::ZZ_p::init(p);


		std::vector<NTL::ZZ> set_zz(setSize); 
		std::vector<block> set(setSize);

		auto generateSet = timer.setTimePoint("generate");

		auto now = std::chrono::high_resolution_clock::now();
    	unsigned int seed = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
		seed ^= static_cast<unsigned int>(getpid());
		srand(seed);
	
		std::string filename = "input/P" + std::to_string(myIdx) + "_" + std::to_string(idxTrial) + ".txt";
		std::remove(filename.c_str());
		 
        std::ofstream outfile(filename);
		std::set<int> party_set;

        if (!outfile) {
            std::cerr << "creat file error: " << filename << std::endl;
            exit(1);
        }
		u64 new_element;
		for(int j = 0; j < setSize; j++)
        {
            do
            {
                new_element = rand() % (2 * setSize);
            }while(party_set.find(new_element)!=party_set.end());

            party_set.insert(new_element);
			set[j] = toBlock(new_element);
			set_zz[j] = NTL::conv<NTL::ZZ>(new_element);
            outfile << new_element << std::endl;
        }
		outfile.close();



		auto setDone = timer.setTimePoint("setDone");


#pragma endregion

		u64 opprfNum = 2 * nParties; 

		std::vector<KkrtNcoOtReceiver> otRecv(opprfNum);
		std::vector<KkrtNcoOtSender> otSend(opprfNum);
		std::vector<OPPRFSender> send(opprfNum);
		std::vector<OPPRFReceiver> recv(opprfNum);


		//###########################################
		//### Offline Phasing-secret sharing 
		//###########################################


		auto start = timer.setTimePoint("start");

		std::vector<std::vector<NTL::ZZ_p>> shares_zz(totalNumShares); 
		std::vector<std::vector<block>>
			sendSSPayLoads(totalNumShares), 
			recvSSPayLoads(totalNumShares);

		for (u64 i = 0; i < recvSSPayLoads.size(); i++)
		{
			recvSSPayLoads[i].resize(setSize);
			sendSSPayLoads[i].resize(setSize);
		}

		if (myIdx == leaderIdx)
		{
			//The leader secretly shares each element x, and each element has a total of n shares.
			for (u64 i = 0; i < setSize; i++)
			{	
				NTL::ZZ_p secret;
				secret = NTL::conv<NTL::ZZ_p>(set_zz[i]);
				std::vector<NTL::ZZ_p> secretShares = ShareSecret(secret, totalNumShares, threshold, p);
				for (u64 j = 0; j < totalNumShares; j++)
				{
					shares_zz[j].resize(setSize);
					shares_zz[j][i] = secretShares[j];
				}
				
			}

			//Convert elements of type ZZ_p to block
			for (u64 i = 0; i < totalNumShares; i++)
			{
				for (u64 j = 0; j < setSize; j++)
				{
					NTL::BytesFromZZ((u8 *)&sendSSPayLoads[i][j], rep(shares_zz[i][j]), sizeof(block));
				}
				
			}
		}

		binSet bins;
		bins.init(myIdx, nParties, setSize, psiSecParam, opt);
		//bins.hashing2Bins(set, 1);
		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

#pragma region base OT
		//########################## 
		//### Base OT
		//##########################

		//phase 1: The leader acts as a sender and executes opprf once with each client, thus distributing n-1 shares of each element
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				send[pIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[pIdx], otRecv[pIdx], prng.get<block>(), false);
			}
		}
		else
		{
			recv[0].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountRecv, otRecv[0], otSend[0], ZeroBlock, false);
		}

		auto initDone = timer.setTimePoint("Phase1: initDone");

#pragma endregion

		//##########################
		//### Hashing
		//##########################


		bins.hashing2Bins(set, 1);

		auto hashingDone = timer.setTimePoint("hashingDone");

#pragma region OPRF

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				send[pIdx].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			recv[0].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		auto getOPRFDone = timer.setTimePoint("Phase1: getOPRFDone");
#pragma endregion


#pragma region SS

		//##########################
		//### online phasing - secretsharing
		//##########################	
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				send[pIdx].sendSSTableBased(pIdx, bins, sendSSPayLoads[pIdx], chls[pIdx], p);
			}
		}
		else
		{
			recv[0].recvSSTableBased(leaderIdx, bins, recvSSPayLoads[0], chls[leaderIdx], p);
		}

		auto getSsDone = timer.setTimePoint("Phase1: secretsharingDone");

		//reset bins
		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};			
			}		
		}

#pragma endregion


#pragma region SendeUpdateValues

		//###########################################
		//### generate values and send to others ####
		//###########################################		

		u64 UpdateValueSize = bins.mSimpleBins.mBins.size();
		std::vector<std::vector<NTL::ZZ_p>> genUpdateValues(UpdateValueSize); 
		std::vector<std::vector<block>> sendUpdateValues(totalNumShares); 
		std::vector<std::vector<block>> recvUpdateValues(totalNumShares);
		std::vector<std::vector<block>> serverUpdateValues(totalNumShares - 1);
		std::vector<block> endValues(UpdateValueSize); 

		for (u64 i = 0; i < recvUpdateValues.size(); i++)
		{
			recvUpdateValues[i].resize(UpdateValueSize);
			sendUpdateValues[i].resize(UpdateValueSize);
		}

		for (u64 i = 0; i < serverUpdateValues.size(); i++)
		{
			serverUpdateValues[i].resize(UpdateValueSize);
		}

		//each party(except leader) generates values used to update values
		if (myIdx != leaderIdx)
		{
			for (u64 i = 0; i < genUpdateValues.size() ; i++)
			{
				genUpdateValues[i].resize(totalNumShares);
				genUpdateValues[i] = GenerateUpdateValues(totalNumShares, threshold, p);
			}

			for (u64 i = 0; i < totalNumShares; i++)
			{
				for (u64 j = 0; j < UpdateValueSize; j++)
				{
				//sendUpdateValues[i][j][k] = genUpdateValues[k][j][i];
				NTL::BytesFromZZ((u8 *)&sendUpdateValues[i][j], rep(genUpdateValues[j][i]), sizeof(block));
				}				
			}		
		}

		//send values to other parties to update shares
		if (myIdx != leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				if (myIdx != pIdx)
				{
					if (pIdx > myIdx)
					{
						auto & chl = *chls[pIdx][0];
						chl.send(sendUpdateValues[pIdx].data(), sendUpdateValues[pIdx].size() * sizeof(block));
					}
					else
					{
						auto & chl = *chls[pIdx][0];
						chl.recv(recvUpdateValues[pIdx].data(), recvUpdateValues[pIdx].size() * sizeof(block));
					}
				}
			}

			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				if (myIdx != pIdx)
				{													
					if (pIdx > myIdx)
					{
						auto & chl = *chls[pIdx][0];
						chl.recv(recvUpdateValues[pIdx].data(), recvUpdateValues[pIdx].size() * sizeof(block));
					}
					else
					{
						auto & chl = *chls[pIdx][0];
						chl.send(sendUpdateValues[pIdx].data(), sendUpdateValues[pIdx].size() * sizeof(block));
					}						
				}																			
			}
		}
		//send to leader
		if (myIdx != leaderIdx)
		{
			auto & chl = *chls[leaderIdx][0];
			chl.send(sendUpdateValues[leaderIdx].data(), sendUpdateValues[leaderIdx].size() * sizeof(block));
		}
		else
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				auto & chl = *chls[pIdx][0];
				chl.recv(recvUpdateValues[pIdx].data(), recvUpdateValues[pIdx].size() * sizeof(block));
			}
			
		}

		for (u64 i = 0; i < UpdateValueSize; i++)
		{
			recvUpdateValues[myIdx][i] = sendUpdateValues[myIdx][i];
		}
		

		//for each bin, add the corresponding values
		
		for (u64 i = 0; i < recvUpdateValues.size(); i++) 
		{
			for (u64 j = 0; j < recvUpdateValues[i].size(); j++) 
			{
 				//  endValues[j] = endValues[j] + recvUpdateValues[i][j];
                NTL::ZZ num1 = NTL::ZZFromBytes((u8 *)&endValues[j], sizeof(block));
                NTL::ZZ num2 = NTL::ZZFromBytes((u8 *)&recvUpdateValues[i][j], sizeof(block));
                
				NTL::ZZ res = AddMod(num1, num2, p);

                NTL::BytesFromZZ((u8 *)&endValues[j], res, sizeof(block));
			}				
		}
#pragma endregion

#pragma region collectionShares
		//######################################
		//### each party updates own shares ####
		//######################################

		u64 hashNum = bins.mSimpleBins.mNumHashes[0] + bins.mSimpleBins.mNumHashes[1];
		std::vector<std::vector<block>> SendValues(hashNum);
		std::vector<std::vector<std::pair<NTL::ZZ,NTL::ZZ>>> totalZZshares(setSize);  

		if (myIdx != leaderIdx)
		{
			for (u64 i = 0; i < SendValues.size(); i++)
			{
				SendValues[i].resize(setSize);
				SendValues[i] = recvSSPayLoads[0]; 
			}

			u64 binStart, binEnd;
			binStart = 0, binEnd = bins.mSimpleBins.mBins.size();

			for (u64 bIdx = binStart; bIdx < binEnd; bIdx++)
			{
				auto& bin = bins.mSimpleBins.mBins[bIdx];
				if (bin.mIdx.size() > 0)
				{
					for (u64 i = 0; i < bin.mIdx.size(); ++i)
					{
						u64 inputIdx = bin.mIdx[i];
						u64 hashIdx = bin.hIdx[i];
						NTL::ZZ num1 = NTL::ZZFromBytes((u8 *)&SendValues[hashIdx][inputIdx], sizeof(block));
                        NTL::ZZ num2 = NTL::ZZFromBytes((u8 *)&endValues[bIdx], sizeof(block));
						NTL::ZZ res = AddMod(num1, num2, p);

                        NTL::BytesFromZZ((u8 *)&SendValues[hashIdx][inputIdx], res, sizeof(block));
									
					}
				}
			}
		}
		else
		{
			SendValues.resize(1);
			SendValues[0].resize(setSize);
			SendValues[0] = sendSSPayLoads[nParties - 1]; 

			std::vector<std::thread>  thrds(1);
			for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
			{
				u64 binStart, binEnd;
				binStart = 0, binEnd = bins.mCuckooBins.mBins.size();
				for (u64 bIdx = binStart; bIdx < binEnd; bIdx++)
				{
					auto& bin = bins.mCuckooBins.mBins[bIdx];
					if (!bin.isEmpty())
					{
						u64 inputIdx = bin.idx();
						//u64 hashIdx = bin.hashIdx();
								
						// SendValues[0][inputIdx] = SendValues[0][inputIdx] + endValues[bIdx];

						NTL::ZZ num1 = NTL::ZZFromBytes((u8 *)&SendValues[0][inputIdx], sizeof(block));
                        NTL::ZZ num2 = NTL::ZZFromBytes((u8 *)&endValues[bIdx], sizeof(block));
                        // NTL::ZZ res = (num1 + num2) % p;
						NTL::ZZ res = AddMod(num1, num2, p);

                        NTL::BytesFromZZ((u8 *)&SendValues[0][inputIdx], res, sizeof(block));			
					}
                }
			}

		}
		auto phase2Done = timer.setTimePoint("Phase2: updatesharesDone");
//##################
//base OT
//##################

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], ZeroBlock, false);
			}
		}
		else
		{
			send[1].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[1], otRecv[1], prng.get<block>(), false);
		}

//#################
//OPRF
//#################

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties ;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[1].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

//###############################
// OPPRF-clients to leader
//###############################

		std::vector<std::vector<block>> endPayLoads(totalNumShares); 
		for (u64 i = 0; i < endPayLoads.size(); i++)
		{
			endPayLoads[i].resize(setSize);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties ;
				recv[thr].recvSSTableBased(pIdx, bins, endPayLoads[pIdx], chls[pIdx], p);
			}
		}
		else
		{
			send[1].sendSSTableBased(leaderIdx, bins, SendValues, chls[leaderIdx], p);
		}
		auto phase3Done = timer.setTimePoint("Phase3: collectsharesDone");

#pragma endregion	



#pragma region Intersection
// ########################################
// reconstruction secret
// ########################################

		std::unordered_set<u64> result;

		if (myIdx == leaderIdx)
		{
			
			endPayLoads[leaderIdx] = SendValues[0];
            	
			for (u64 i = 0; i < totalZZshares.size(); i++)
			{
				totalZZshares[i].resize(totalNumShares);
				for (u64 j = 0; j < totalZZshares[i].size(); j++)
				{
					totalZZshares[i][j].first = NTL::conv<NTL::ZZ>(j+1);			
					totalZZshares[i][j].second = NTL::ZZFromBytes((u8 *)&endPayLoads[j][i], sizeof(block));
				}
			}


			std::vector<std::vector<int>> all_combinations;
			get_combinations_iterative(totalNumShares - 1, threshold - 1, all_combinations);

			for(int i = 0; i < all_combinations.size(); i++)
			{
				all_combinations[i].push_back(leaderIdx);
			}

			for (int eIdx = 0; eIdx < setSize; eIdx++) 
			{
				u64 count = 0;
				for (const auto& current_combination : all_combinations) 
				{
					count++;
					int res = reconstruct_secret(current_combination, totalZZshares[eIdx], p, set_zz[eIdx]);
					if (res == 1) {
						result.insert(eIdx); 
						break; 
					}
				}
			}	
		}

		auto getIntersection = timer.setTimePoint("getIntersection");


		if(myIdx == leaderIdx)
		{
			std::unordered_map<std::string, std::unordered_set<std::string>> element_to_parties;
			const char* dir_path = "./input";
			DIR* dir = opendir(dir_path);
			if (dir == NULL) 
			{
				perror("opendir error");
				exit(-1);
			}
			struct dirent* entry;
			std::string leader = "P" + std::to_string(leaderIdx) + "_" + std::to_string(idxTrial)+ ".txt";
			std::vector<std::string> element_files(nParties);
			for(int i = 0; i < element_files.size(); i++)
			{
				element_files[i] = "P" + std::to_string(i)  + "_" + std::to_string(idxTrial)+ ".txt";
			}
			while ((entry = readdir(dir)) != NULL) 
			{
				std::string filename = entry->d_name;

				
				if(std::find(element_files.begin(), element_files.end(), std::string(filename))!= element_files.end())
				{
					
					std::string file_path = std::string(dir_path) + "/" + filename;
					
					std::ifstream file(file_path);
					
					if (!file.is_open()) 
					{
						std::cerr << "Failed to open file: " << file_path << std::endl;
						continue;
					}

					std::string element;
					while (getline(file, element)) 
					{
						element_to_parties[element].insert(filename);
					}

					// std::remove(file_path.c_str());
				}
			}

			closedir(dir);

			
			
			
			int count = 0;
		
			for (const auto& pair : element_to_parties) 
			{
				if (pair.second.size() >= threshold && pair.second.count(leader) > 0) 
				{
					count++;
				}
			}
			expected_intersection = count;
			std::cout<<"the number of intersection is "<<result.size()<<std::endl;
			std::cout<<"the number of expected_intersection is "<<expected_intersection<<std::endl;
		}

		if (myIdx == 0  || myIdx == leaderIdx)
		{
			auto genSetTime = std::chrono::duration_cast<std::chrono::milliseconds>(setDone - generateSet).count();
			auto phase1 = std::chrono::duration_cast<std::chrono::milliseconds>(getSsDone - start).count(); // secret share + opprf
			auto phase2 = std::chrono::duration_cast<std::chrono::milliseconds>(phase2Done - getSsDone).count(); // update shares
			auto phase3 = std::chrono::duration_cast<std::chrono::milliseconds>(phase3Done - phase2Done).count(); // opprf
			auto phase4 = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - phase3Done).count(); // reconstruction


			
			double time = phase1 + phase2 + phase3 + phase4;
			double share_time = phase1 + phase2 + phase3;
			double recon_time = phase4;

			time /= 1000;
			share_time /= 1000;
			recon_time /= 1000;

			eachTime[idxTrial] = time; //s
			eachShareTime[idxTrial] = share_time;
			eachReconTime[idxTrial] = recon_time;

			dataSent = 0;
			dataRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) 
				{
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}

			if (myIdx == leaderIdx) 
			{
				// osuCrypto::Log::out << "#Output Intersection: " << result.size() << osuCrypto::Log::endl;
				// osuCrypto::Log::out << "#Expected Intersection: " << expected_intersection << osuCrypto::Log::endl;
				num_intersection = result.size();
				std::string filename = "time_leader.txt";
				std::ofstream oFile;
				oFile.open(filename,std::ios::out|std::ios::app);
				oFile<<"numParty: "<< nParties << " "
					<< "threshold: "<< threshold << " "
					<< "setSize: " << setSize << "\n"
					<< "Expected Intersection: " << expected_intersection << "\n"
					<< "Output Intersection: " << result.size() << "\n"
					<<"Phase1 time: " << phase1 << " ms\n"
					<<"Phase2 time: " << phase2 << " ms\n"
					<<"Phase3 time: " << phase3 << " ms\n"
					<<"Phase4 time: " << phase4 << " ms\n"
					<<"share time: " << share_time << " s\n"
					<<"recon time: " << recon_time << " s\n"
					<< "Total time: " << time << " s\n"
					<< "------------------\n";
			}

			std::cout << "setSize: " << setSize << "\n"
				<<"Phase1 time: " <<phase1 << " ms\n"
				<<"Phase2 time: " <<phase2 << " ms\n"
				<<"Phase3 time: " <<phase3 << " ms\n"
				<<"Phase4 time: " <<phase4 << " ms\n"
				<<"share time: " << share_time << " ms\n"
				<<"recon time: " << recon_time << " ms\n"
				<< "Total time: " << time << " s\n"

				<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
				<< "------------------\n";


				
			totalTime += time;
			totalShareTime += share_time;
			totalReconTime += recon_time;
		}

#pragma endregion	
		

		//free
		deep_clear(shares_zz);
		deep_clear(sendSSPayLoads);
		deep_clear(recvSSPayLoads);
		deep_clear(genUpdateValues);
		deep_clear(sendUpdateValues);
		deep_clear(recvUpdateValues);
		deep_clear(serverUpdateValues);
		deep_clear(SendValues);
		deep_clear(totalZZshares);
		deep_clear(endPayLoads);


		release_vector(set_zz);
		release_vector(set);
		release_vector(otRecv);
		release_vector(otSend);
		release_vector(send);
		release_vector(recv);
		release_vector(endValues);
		
		std::unordered_set<u64>().swap(result);


	}


	std::cout << osuCrypto::IoStream::lock;
	if (myIdx == 0 || myIdx == leaderIdx) 
	{
		totalAvgTime = totalTime / nTrials;
		totalAvgShareTime = totalShareTime / nTrials;
		totalAvgReconTime = totalReconTime / nTrials;

		for(u64 i = 0; i < nTrials ; i++)
		{
			total_sd += pow(eachTime[i] - totalAvgTime, 2);
			total_share_sd += pow(eachShareTime[i] - totalAvgShareTime, 2);
			total_recon_sd += pow(eachReconTime[i] - totalAvgReconTime, 2);

		}

		total_sd = sqrt(total_sd / nTrials);
		total_share_sd = sqrt(total_share_sd / nTrials);
		total_recon_sd = sqrt(total_recon_sd / nTrials);

		std::cout << "=========avg==========\n";
		runtime << "=========avg==========\n";
		runtime << "numParty: " << nParties
			<< "  threshold: " << threshold
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n";
		
		if (myIdx == 0)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";

		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
			runtime << "Leader Idx: " << myIdx << "\n";
		}

		std::cout << "numParty: " << nParties
			<< "  threshold: " << threshold
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"

			<< "Total time: " << totalAvgTime << " s\n"
			<< "total_sd: " << total_sd << " s\n"

			<<"share time: " << totalAvgShareTime << " s\n"
			<<"total_share_sd: " << total_share_sd<< " s\n"

			<<"recon time: " << totalAvgReconTime << " s\n"
			<< "total_recon_sd: "<< total_recon_sd<< " s\n"
			<< "------------------\n";


			runtime << "numParty: " << nParties
			<< "  threshold: " << threshold
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"

			<< "Total time: " << totalAvgTime  << " s\n"
			<< "total_sd: " << total_sd << " s\n"

			<<"share time: " << totalAvgShareTime << " s\n"
			<<"total_share_sd: " << total_share_sd<< " s\n"
			
			<<"recon time: " << totalAvgReconTime << " s\n"
			<< "total_recon_sd: "<< total_recon_sd<< " s\n"
			<< "------------------\n";

			runtime.close();
	}

	
	std::cout << IoStream::unlock;

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();

}

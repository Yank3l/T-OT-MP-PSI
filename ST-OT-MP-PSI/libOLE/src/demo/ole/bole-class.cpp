
/**
@file ole-pipeline.cpp  --  Benchmark of OLE pipeline stages
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "pke/ole.h"
#include "pke/gazelle-network.h"
#include "utils/debug.h"

#include <boost/multiprecision/cpp_int.hpp>
using uint256_t = boost::multiprecision::uint256_t;

using namespace lbcrypto;
using namespace osuCryptoNew;

string addr = "localhost";
uint32_t port = 9090;

const ui32 numBlocks = pow(2,1);

const ui32 numProtocols = 1;
const double std_dev = 3.2;
const ui128 plainModulos = (ui128)2820882433 * 2183135233 * 3997745153 * 4294475777;
std::vector<ui64> FourModulo = {2820882433, 2183135233, 3997745153, 4294475777};
//
template <typename SchemeType>
void bole_receiver() {

    double start, end;

    //
    // Networking Setup
    //
    cout << "Receiver\n";
    IOService ios;
    Session sess(ios, addr, port, EpMode::Server);
    Channel chl = sess.addChannel();

    //
    // Scheme Setup
    //

    SchemeType scheme(std_dev);

    //
    // Key Setup
    //
    using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
    using SecretKey = typename SchemeType::SecretKey;

    start = currentDateTime();
    KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
    end = currentDateTime();
    cout << "Client key generation: " << (end - start) << " ms\n";

    sendPublicKey(kpSeeded.pkSeeded, chl);
    cout << "Client sent public key\n";
    SecretKey& sk = kpSeeded.sk;

    //
    // Input generation
    //
    using encoding_context_t = typename SchemeType::encoding_context_t;
    using encoding_input_t = typename encoding_context_t::encoding_input_t; 

    BOLEReceiverInput<encoding_input_t> receiverInput(numBlocks);
    for (ui32 i = 0; i < numBlocks; i++) 
        receiverInput.x[i] = encoding_context_t::generateRandomInput();
    //
    

    std::vector<std::vector<ui128>> ReInput(numBlocks);
    ui32 numOLE = pow(2,13);
    for (ui32 i = 0; i < numBlocks; i++)
    {
        ReInput[i].resize(numOLE);
        get_dug_array_128(ReInput[i].data(), numOLE, plainModulos);
    }
    
    FourBOLEReceiverInputs<encoding_input_t> FourInputs(numBlocks); 
    

    FourInputs.processModule(ReInput);

    FourInputs.receiverInputs[0].send(chl);
    // // std::cout<<"ReInput[0][10]"<<ReInput[0][10]<<std::endl;
    std::vector<std::string> labels = {"ReInput1", "ReInput2", "ReInput3", "ReInput4"};
    for (size_t i = 0; i < FourInputs.receiverInputs.size(); ++i) {
        std::cout << labels[i] << "[1][10]: " << FourInputs.receiverInputs[i].x[1].vals[10] << std::endl;
    }
 
    //
    // BOLE Online
    // 

    BOLEReceiverOutput<encoding_input_t> bole_output;

    double totalTime = 0;
    for (ui32 i = 0; i < numProtocols; i++) {
        start = currentDateTime();
        bole_output = BOLEReceiver::online(FourInputs.receiverInputs[0], sk, scheme, chl);
        // bole_output = BOLEReceiver::online(FourInputs, sk, scheme, chl);
        end = currentDateTime();
        totalTime += (end - start);
    }
    double time = totalTime / numProtocols;


    bole_output.send(chl);

    cout << "BOLE online time = " << time << " ms\n";
    cout << "Num OLEs = " << numBlocks*scheme.phim << endl;
    cout << "per OLE online time = " << 1000*(time)/(numBlocks*scheme.phim) << " us\n"; 

    chl.close();
    sess.stop();
    ios.stop();
};

template <typename SchemeType>
void bole_sender() {

    // double start, end;

    //
    // Networking Setup
    //
    cout << "Sender\n";
    IOService ios;
    Session sess(ios, addr, port, EpMode::Client);
    Channel chl = sess.addChannel();

    //
    // Scheme Setup
    //

    const SchemeType scheme(std_dev);

    // Receive public key
    using SeededPublicKey= typename SchemeType::PublicKeySeeded;
    using PublicKey = typename SchemeType::PublicKey;
    SeededPublicKey seededPK;
    receivePublicKey(seededPK, chl);
    PublicKey pk = seededPK.expand();

    cout << "public key received\n";


    //
    // Data Generation
    //
    using encoding_context_t = typename SchemeType::encoding_context_t;
    using encoding_input_t = typename encoding_context_t::encoding_input_t;

    vector<encoding_input_t> aVecs(numBlocks);
    vector<encoding_input_t> bVecs(numBlocks);
    for (ui32 i = 0; i < numBlocks; i++) {
        aVecs[i] = encoding_context_t::generateRandomInput();
        bVecs[i] = encoding_context_t::generateRandomInput();
    }

    BOLESenderInput<encoding_input_t> senderInput(aVecs, bVecs);

    auto recvIn =  BOLEReceiverInput<encoding_input_t>::receive(chl);

    BOLEReceiverOutput<encoding_input_t> correct = bole_pt<encoding_context_t>(recvIn, senderInput);

    //
    // Run OLE
    //

    cout << "Sender beginning online\n";
    double totalTime = 0;
    double start, end;
    for (ui32 i = 0; i < numProtocols; i++) {
        start = currentDateTime();
        BOLESender::online(senderInput, pk, scheme, chl);
        end = currentDateTime();
        totalTime += end-start;
    }
    double time = totalTime/numProtocols;
    cout << "Server online time = " << time << " ms\n";
    cout << "Server per BOLE time = " << (time)/(scheme.phim*numBlocks) * 1000 << " us\n";

    auto bole_output = BOLEReceiverOutput<encoding_input_t>::receive(chl);

    assert(BOLEReceiverOutput<encoding_input_t>::eq(bole_output, correct));
    cout << "BOLE computed correct result\n";

    chl.close();
    sess.stop();
    ios.stop();
};


template <typename SchemeType>
void launch_ole_batch(int argc, char** argv) {
    if (argc == 1) {
		vector<thread> thrds(2);
		thrds[0] = thread([]() { bole_receiver<SchemeType>(); });
		thrds[1] = thread([]() { bole_sender<SchemeType>(); });

        for (auto& thrd : thrds)
            thrd.join();
	} else if(argc == 2) {
		int role = atoi(argv[1]); // 0: send, 1: recv
		role ? bole_sender<SchemeType>() : bole_receiver<SchemeType>();
	} else if(argc == 3) {
		int role = atoi(argv[1]); // 0: send, 1: recv
		role ? bole_sender<SchemeType>() : bole_receiver<SchemeType>();
	}
    else {
      cout << "this program takes a runtime argument.\n\n"
        << "to run the OLE protocol, run\n\n"
        << "    ole-online [0|1]\n\n"
        << "the optional {0,1} argument specifies in which case the program will\n"
        << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
        << "    bole-online 0\n\n"
        << "    bole-online 1\n\n"
        << "These programs are fully networked and try to connect at " << addr << ":" << port << ".\n"
        << endl;
    }
};

template <typename ptT, ptT p, ui32 numLimbs>
void run_bole(int argc, char** argv, const bool comm_optimized) {

    constexpr ui32 logn = 13;

    cout << "\n================================================\n";
    cout << "Running BOLE logp="<<log2(p)<<"\n";
    cout << "================================================\n";

    typedef DCRT_Poly_Ring<params<ptT>, logn> PlaintextRing;
    typedef EncodingContext<PlaintextRing, p> encoding_context_t;

    typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p> dcrt_params_t;
    typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

    // if (comm_optimized) launch_ole_batch_comm_opt<SchemeType>(argc, argv);
	// else 
    // std::cout<<"argc: "<<argc<<", argv: "<<argv<<std::endl;
    // launch_ole_batch<SchemeType>(argc, argv);
};

template<ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType1>
BOLEReceiverOutput<typename SchemeType1::encoding_context_t::encoding_input_t> ReceiverOnline(
    const BOLEReceiverInput<typename SchemeType1::encoding_context_t::encoding_input_t>& input,
    const typename SchemeType1::SecretKey& sk,
    const SchemeType1& scheme_origin, 
    Channel& chl
) {
    
    constexpr ui32 logn_const = logn;

   
    typedef DCRT_Poly_Ring<params<ui64>, logn_const> PlaintextRing;
    static_assert(std::is_integral<decltype(p)>::value, "p must be an integral constant");

    typedef EncodingContext<PlaintextRing, p> encoding_context_t;
    typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p> dcrt_params_t;
    typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

    
    SchemeType scheme(std_dev);
    using encoding_context_t = typename SchemeType::encoding_context_t;
    using encoding_input_t = typename encoding_context_t::encoding_input_t;

    input.send(chl);

    
    BOLEReceiverOutput<encoding_input_t> output;
    output = BOLEReceiver::online(input, sk, scheme, chl);
    output.send(chl);
    return output;


}

template<ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType1>
void SenderOnline(
    BOLESenderInput<typename SchemeType1::encoding_context_t::encoding_input_t>& input, 
    const typename SchemeType1::PublicKey& pk,
    const SchemeType1& scheme_origin, 
    Channel& chl
){
    constexpr ui32 logn_const = logn;

    typedef DCRT_Poly_Ring<params<ui64>, logn_const> PlaintextRing;
    static_assert(std::is_integral<decltype(p)>::value, "p must be an integral constant");

    typedef EncodingContext<PlaintextRing, p> encoding_context_t;
    typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p> dcrt_params_t;
    typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

    SchemeType scheme(std_dev);

    using encoding_context_t = typename SchemeType::encoding_context_t;
    using encoding_input_t = typename encoding_context_t::encoding_input_t;

    auto recvIn =  BOLEReceiverInput<encoding_input_t>::receive(chl); //receiver_x
    BOLEReceiverOutput<encoding_input_t> correct = bole_pt<encoding_context_t>(recvIn, input);  //input:(a,b)

    BOLESender::online(input, pk, scheme, chl);

    auto bole_output = BOLEReceiverOutput<encoding_input_t>::receive(chl);//receiver_output

    assert(BOLEReceiverOutput<encoding_input_t>::eq(bole_output, correct));
    cout << "BOLE computed correct result\n";

}


int main(int argc, char** argv) {
    CHECK_DEBUG_VERBOSE;

    const bool comm_optimized = false;



    constexpr ui32 logn = 13;


    constexpr ui64 p1 = 2820882433ULL;
    constexpr ui64 p2 = 2183135233ULL;
    constexpr ui64 p3 = 3997745153ULL;
    constexpr ui64 p4 = 4294475777ULL;
    // vector<ui64> FourModulo_ = {2820882433, 2183135233, 3997745153, 4294475777};
    // ui32 numLimbs = 4;

    std::cout << "\n================================================\n";
    std::cout << "Running BOLE logp=" << log2(p1) << "\n";
    std::cout << "================================================\n";



    vector<thread> thrds(2);
	thrds[0] = thread([]() {

        
        typedef DCRT_Poly_Ring<params<ui64>, logn> PlaintextRing;
        typedef EncodingContext<PlaintextRing, p1> encoding_context_t;

        typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
        typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p1> dcrt_params_t;
        typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

        double start, end;
        vector<ui64> FourModulo_ = {2820882433, 2183135233, 3997745153, 4294475777};

        //
        // Networking Setup
        //
        cout << "Receiver\n";
        IOService ios;
        Session sess(ios, addr, port, EpMode::Server);
        Channel chl = sess.addChannel();    
        
        //
        // Scheme Setup
        //

        SchemeType scheme(std_dev);  

        //
        // Key Setup
        //
        using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
        using SecretKey = typename SchemeType::SecretKey;

        start = currentDateTime();
        KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
        end = currentDateTime();
        cout << "Client key generation: " << (end - start) << " ms\n";

        sendPublicKey(kpSeeded.pkSeeded, chl);
        cout << "Client sent public key\n";
        SecretKey& sk = kpSeeded.sk;   

        //
        // Input generation
        //
        using encoding_context_t = typename SchemeType::encoding_context_t;
        using encoding_input_t = typename encoding_context_t::encoding_input_t; 

        
        //Receiver Input
        std::vector<std::vector<ui128>> ReInput(numBlocks);
        ui32 numOLE = pow(2,13);
        for (ui32 i = 0; i < numBlocks; i++)
        {
            ReInput[i].resize(numOLE);
            get_dug_array_128(ReInput[i].data(), numOLE, plainModulos);
        }   

        FourBOLEReceiverInputs<encoding_input_t> FourInputs(numBlocks); 
    
        FourInputs.processModule(ReInput);

        // FourInputs.receiverInputs[0].send(chl);

    

        //
        // BOLE Online
        // 

        std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));
         double totalTime = 0;    
        for (ui32 i = 0; i < numProtocols; i++)
        {
            start = currentDateTime();
            // FourOutputs[0] = BOLEReceiver::online(FourInputs.receiverInputs[0], sk, scheme, chl);
            FourOutputs[0] = ReceiverOnline<2820882433ULL, 13, 4, SchemeType>(
                FourInputs.receiverInputs[0], sk, scheme, chl
            );
            FourOutputs[1] = ReceiverOnline<2183135233ULL, 13, 4, SchemeType>(
                FourInputs.receiverInputs[1], sk, scheme, chl
            );
            FourOutputs[2] = ReceiverOnline<3997745153ULL, 13, 4, SchemeType>(
                FourInputs.receiverInputs[2], sk, scheme, chl
            );
            FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(
                FourInputs.receiverInputs[3], sk, scheme, chl
            );
        

        std::vector<std::string> labels_out = {"Reoutput1", "Reoutput2", "Reoutput3", "Reoutput4"};
        for (size_t i = 0; i < FourOutputs.size(); ++i) {
            std::cout << labels_out[i] << "[1][10]: " << FourOutputs[i].cBlocks[1][10] << std::endl;
        }


        
        }

        double time = totalTime / numProtocols;       
        cout << "BOLE online time = " << time << " ms\n";
        cout << "Num OLEs = " << numBlocks*scheme.phim << endl;
        cout << "per OLE online time = " << 1000*(time)/(numBlocks*scheme.phim) << " us\n"; 

        // scheme.dcrt_params.compressPlaintext(combine[0], plainModulos);


        //correct result
        std::vector<std::vector<ui128>> ReceiveInput_aVecs(numBlocks, std::vector<ui128>(encoding_input_t::phim));
        std::vector<std::vector<ui128>> ReceiveInput_bVecs(numBlocks, std::vector<ui128>(encoding_input_t::phim));

        for (size_t i = 0; i < numBlocks; ++i) {
         
            chl.recv(ReceiveInput_aVecs[i].data(), encoding_input_t::phim);

        
            chl.recv(ReceiveInput_bVecs[i].data(), encoding_input_t::phim);
        }


        for (ui32 i = 0; i < numBlocks; i++)
        {
            
            for (ui32 j = 0; j < encoding_input_t::phim; j++)
            {

                for (ui32 k = 0; k < 4; k++)
                {
                    ui32 a = ((ReceiveInput_aVecs[i][j]>>((3-k) * 32 ))& 0xFFFFFFFF) % FourModulo_[k];
                    ui32 b = ((ReceiveInput_bVecs[i][j]>>((3-k) * 32 ))& 0xFFFFFFFF) % FourModulo_[k];

                    ui32 x = static_cast<ui32>((ReInput[i][j]>>((3-k) * 32 ))& 0xFFFFFFFF) % FourModulo_[k];

                    ui64 res = ((ui64)a*(ui64)x + (ui64)b )% FourModulo_[k];


                    if(res != FourOutputs[k].cBlocks[i][j])
                    {
                        std::cout<<"error"<<std::endl;

                    }
                }
                
                
            }
            
            
        }
        
            
        

        chl.close();
        sess.stop();
        ios.stop();        
    });
	thrds[1] = thread([]() { 

        typedef DCRT_Poly_Ring<params<ui64>, logn> PlaintextRing;
        typedef EncodingContext<PlaintextRing, p1> encoding_context_t;

        typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
        typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p1> dcrt_params_t;
        typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

        //
        // Networking Setup
        //
        cout << "Sender\n";
        IOService ios;
        Session sess(ios, addr, port, EpMode::Client);
        Channel chl = sess.addChannel();

        //
        // Scheme Setup
        //

        const SchemeType scheme(std_dev);

        // Receive public key
        using SeededPublicKey= typename SchemeType::PublicKeySeeded;
        using PublicKey = typename SchemeType::PublicKey;
        SeededPublicKey seededPK;
        receivePublicKey(seededPK, chl);
        PublicKey pk = seededPK.expand();

        cout << "public key received\n";


        //
        // Data Generation
        //
        using encoding_context_t = typename SchemeType::encoding_context_t;
        using encoding_input_t = typename encoding_context_t::encoding_input_t;

        std::vector<std::vector<ui128>> SendInput_aVecs(numBlocks), SendInput_bVecs(numBlocks);
        ui32 numOLE = pow(2,13);
        for (ui32 i = 0; i < SendInput_aVecs.size(); i++)
        {
            SendInput_aVecs[i].resize(numOLE);
            SendInput_bVecs[i].resize(numOLE);
            get_dug_array_128(SendInput_aVecs[i].data(), numOLE, plainModulos);
            get_dug_array_128(SendInput_bVecs[i].data(), numOLE, plainModulos);
        }

        std::vector<std::vector<encoding_input_t>> aVecs(4);
        std::vector<std::vector<encoding_input_t>> bVecs(4);

        for (ui32 i = 0; i < 4; i++)
        {
            aVecs[i].resize(numBlocks);
            bVecs[i].resize(numBlocks);

            for (ui32 j = 0; j < numBlocks; j++)
            {
               for (ui32 k = 0; k < encoding_input_t::phim; k++)
               {
                    aVecs[i][j].vals[k] = ((SendInput_aVecs[j][k] >> ((3-i)*32))& 0xFFFFFFFF)% FourModulo[i];
                    bVecs[i][j].vals[k] = ((SendInput_bVecs[j][k] >> ((3-i)*32))& 0xFFFFFFFF)% FourModulo[i];
               }
               
            }
            
        }

       
        boost::multiprecision::uint128_t input_a = SendInput_aVecs[1][10];
        boost::multiprecision::uint128_t input_b = SendInput_bVecs[1][10];
        std::cout<<"a is "<<input_a<<std::endl;
        std::cout<<"b is "<<input_b<<std::endl;
        std::vector<std::string> labels_a = {"SendInputa_1", "SendInputa_2", "SendInputa_3", "SendInputa_4"};
        for (size_t i = 0; i < aVecs.size(); ++i) {
            std::cout << labels_a[i] << "[1][10]: " << aVecs[i][1].vals[10] << std::endl;
        }
               
        std::vector<std::string> labels_b = {"SendInputb_1", "SendInputb_2", "SendInputb_3", "SendInputb_4"};
        for (size_t i = 0; i < bVecs.size(); ++i) {
            std::cout << labels_b[i] << "[1][10]: " << bVecs[i][1].vals[10] << std::endl;
        }
       

        std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
        for (ui32 i = 0; i < 4; i++)
        {
           FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i],bVecs[i]));
        }
        

        
               double totalTime = 0;
        double start, end;
        for (ui32 i = 0; i < numProtocols; i++) {
            start = currentDateTime();    
            SenderOnline<2820882433ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, chl);
            SenderOnline<2183135233ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, chl);
            SenderOnline<3997745153ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, chl);
            SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, chl);
            end = currentDateTime();
            totalTime += end-start;
        }
        double time = totalTime/numProtocols;
        cout << "Server online time = " << time << " ms\n";
        cout << "Server per BOLE time = " << (time)/(scheme.phim*numBlocks) * 1000 << " us\n";
 

  


       
        for (size_t i = 0; i < numBlocks; ++i) {
           
            const ui128* dataA = SendInput_aVecs[i].data();
            u64 lengthA = SendInput_aVecs[i].size();
            chl.send(dataA, lengthA);

           
            const ui128* dataB = SendInput_bVecs[i].data();
            u64 lengthB = SendInput_bVecs[i].size();
            chl.send(dataB, lengthB);
        }

        



        chl.close();
        sess.stop();
        ios.stop();
    });

    for (auto& thrd : thrds)
        thrd.join();
    return 0;

}

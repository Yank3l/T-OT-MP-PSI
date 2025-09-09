
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "OtBinMain.h"
#include "bitPosition.h"

#include <numeric>
#include "Common/Log.h"
//int miraclTestMain();


void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t For simulation (5 parties <=> 5 terminals): " << std::endl;;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;

}
int main(int argc, char** argv)
{
	
	
	u64 trials = 10;
	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

	u64 nParties, threshold, opt_basedOPPRF, setSize, isAug;
	u64 roundOPPRF;


	switch (argc) {
	case 9: //ET-OT-MP-PSI
		
		if (argv[1][0] == '-' && argv[1][1] == 'n')
			nParties = atoi(argv[2]);
		else
		{
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 't')
			threshold = atoi(argv[4]);
		else
		{
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 'm')
			setSize = 1 << atoi(argv[6]);
		else
		{
			usage(argv[0]);
			return 0;
		}

		if (argv[7][0] == '-' && argv[7][1] == 'p') {
			u64 pIdx = atoi(argv[8]);

		if (argv[3][1] == 't')
			{
				//cout << nParties << " " << tParties << " " << setSize << " " << pIdx << "\n";
				tparty(pIdx, nParties, threshold, setSize, trials);
			}
		}
		else
		{
			usage(argv[0]);
			return 0;
		}
		break;
	}

	return 0;
}

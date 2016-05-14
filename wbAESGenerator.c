#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "matrixOperations.h"

//This program generates the tables for the white-box implementation of Luo-Lai-You and write them into table.h
//It uses some definition or function of the AES program found on https://github.com/kokke/tiny-AES128-C namely for the S-Box, basic operations in AES field and the standard AES key schedule
//The key to used is to pass as an argument to the program in the format 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef, if not a standard key will be used

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

//These defines are here to include or not security features of the tables (0 to deactivate, 1 to activate)

#define ENCODINGS 0
#define MIXING_BIJECTIONS 1
#define EXTERNAL_ENCODINGS 0

// The array that stores the round keys.
static uint8_t RoundKey[176];

// The Key input to the AES Program
static const uint8_t* Key;

static uint8_t SRMatrix[128][128] = {0};
static uint8_t XOR[256] = {0};
static uint8_t XOR3[256][16] = {0};

//Mappings for table construction
uint8_t LMappings[10][8][16][16] = {0};
uint8_t RMappings[10][8][32][32] = {0};

uint8_t LLInvMappings[10][128][128] = {0};
uint8_t RInvMappings[10][8][32][32] = {0};

uint8_t IN[128][128] = {0};
uint8_t OUT[128][128] = {0};
uint8_t INOpposite[128][128] = {0};
uint8_t OUTOpposite[128][128] = {0};
uint8_t INByteOpposite[128][16] = {0};
uint8_t OUTByteOpposite[128][16] = {0};

uint8_t in[18752][16] = {0};
uint8_t out[18752][16] = {0};

uint8_t inputEncodings[32][16] = {0};
uint8_t outputEncodings[32][16] = {0};

//Tables
uint8_t TSRRound1[4][4][256][16];
uint8_t TSR[10][4][8][256][16];
uint8_t nTMC[10][8][256][256][4];
uint8_t TXORRound1[32][5][256];
uint8_t TXOR3Round1[32][5][256][16];
uint8_t TXOR[10][32][13][256];
uint8_t TXOR3[10][32][9][256][16];

static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t Rcon[255] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };

static uint8_t Tboxes[10][16][256] = {0};

//return the SBox value
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}

//multiplication by X (02) in AES field
static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

//multiplication x*y in AES field
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

// This function produces Nb(Nr+1) round keys. 
static void KeyExpansion(void)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for(i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

//This function apply ShiftRows to a round key
static void modifyRoundKey(uint8_t round)
{
	uint8_t temp;

	// Rotate first row 1 columns to left  
	temp           = RoundKey[round * Nb * 4+1];
	RoundKey[round * Nb * 4+1] = RoundKey[round * Nb * 4+Nb*1+1];
	RoundKey[round * Nb * 4+Nb*1+1] = RoundKey[round * Nb * 4+Nb*2+1];
	RoundKey[round * Nb * 4+Nb*2+1] = RoundKey[round * Nb * 4+Nb*3+1];
	RoundKey[round * Nb * 4+Nb*3+1] = temp;

	// Rotate second row 2 columns to left  
	temp           = RoundKey[round * Nb * 4+2];
	RoundKey[round * Nb * 4+2] = RoundKey[round * Nb * 4+Nb*2+2];
	RoundKey[round * Nb * 4+Nb*2+2] = temp;

	temp       = RoundKey[round * Nb * 4+Nb*1+2];
	RoundKey[round * Nb * 4+Nb*1+2] = RoundKey[round * Nb * 4+Nb*3+2];
	RoundKey[round * Nb * 4+Nb*3+2] = temp;

	// Rotate third row 3 columns to left
	temp       = RoundKey[round * Nb * 4+3];
	RoundKey[round * Nb * 4+3] = RoundKey[round * Nb * 4+Nb*3+3];
	RoundKey[round * Nb * 4+Nb*3+3] = RoundKey[round * Nb * 4+Nb*2+3];
	RoundKey[round * Nb * 4+Nb*2+3] = RoundKey[round * Nb * 4+Nb*1+3];
	RoundKey[round * Nb * 4+Nb*1+3] = temp;
}

//This function construct all the TBoxes, it applies ShiftRows to all the round key first and then proceeds to compute for every values the result of AddRoundKey followed by SubBytes
void constructTBox()
{
	uint8_t i, j;
	int k;
	for (i = 1 ; i < Nr ; i++)
	{
		modifyRoundKey(i-1);
		for (j = 0; j < Nb*4; j++)
		{
			for (k = 0; k < 256; k++)
			{
				Tboxes[i-1][j][k] = getSBoxValue(k^RoundKey[(i-1) * Nb * 4 + j]);
			}
		}
	}
	modifyRoundKey(Nr-1);
	for (j = 0; j < Nb*4; j++)
	{
		for (k = 0; k < 256; k++)
		{
			Tboxes[Nr-1][j][k] = getSBoxValue(k^RoundKey[(Nr-1) * Nb * 4 + j])^RoundKey[Nr * Nb * 4 + j];
		}
	}
}

//return the TBox values
static uint8_t getTBoxValue(int round, int byte, uint8_t num)
{
  return Tboxes[round][byte][num];
}

//construct the matrix representing the ShiftRows operation in GF(2)
static void constructSRMatrix()
{
	int i,j,k = 0;
	for (i=0;i<128;i+=8)
	{
		for (j=0;j<8;j++)
		{
			SRMatrix[i+j][8*k+j] = 1;
		}
		k=(k+5)%16;
	}
}

//construct non encoded XOR and XOR3 tables
static void constructXor()
{
	int i,j;
	for (i=0;i<256;i++)
	{
		XOR[i]=(i&0x0F)^((i&0XF0)>>4);
		for(j=0;j<16;j++)
		{
			XOR3[i][j]=XOR[i]^j;
		}
	}
}

//transform one byte into 8 bits, bits must be bits[8][1]
static void transformByteToBits(const uint8_t byte, uint8_t (* bits)[1])
{
	int i;
	for (i=0;i<8;i++)
	{
		(*bits)[i]=(byte&(0x01<<i))>>i;
	}
}

//transform 8 bits into one byte
static void transformBitsToByte(uint8_t (* const bits)[1], uint8_t *byte)
{
	int i;
	*byte=0;
	for (i=0;i<8;i++)
	{
		*byte+=(*bits)[i]<<i;
	}
}

//This function construct the mixing bijections L and their inverse
static void constructLMappings()
{
	int round,table;
	int i,j;
	uint8_t LInvMappings[8][16][16];
	for (round=0;round<Nr;round++)
	{
		for (table=0;table<8;table++)
		{
			if(MIXING_BIJECTIONS)
			{
				generateInvertibleMatrix(16,LMappings[round][table],LInvMappings[table]);
			}
			else
			{
				constructIdentity(16,LMappings[round][table]);
				constructIdentity(16,LInvMappings[table]);
			}
		}
		for (i=0;i<128;i++)
		{
			for (j=0;j<128;j++)
			{
				if(i/16==j/16)
				{
					LLInvMappings[round][i][j] = LInvMappings[i/16][i%16][j%16];
				}
				else
				{
					LLInvMappings[round][i][j] = 0;
				}
			}
		}
	}
}

//This function construct the mixing bijections R and their inverse
static void constructRMappings()
{
	int round,table;
	int i,j;
	uint8_t M[32][32];
	uint8_t I[32][32];	
	for (round=0;round<Nr;round++)
	{
		for (table=0;table<8;table++)
		{
			if(MIXING_BIJECTIONS)
			{
				generateInvertibleMatrix(32,RMappings[round][table],RInvMappings[round][table]);
			}
			else
			{
				constructIdentity(32,RMappings[round][table]);
				constructIdentity(32,RInvMappings[round][table]);
			}
		}
	}
}

//This function construct the external encodings IN and OUT and their inverse
static void constructExternalEncodings()
{
	int i,j;
	if(EXTERNAL_ENCODINGS)
	{	
		generateInvertibleMatrix(128,IN,INOpposite);
		generateInvertibleMatrix(128,OUT,OUTOpposite);
	}
	else
	{
		constructIdentity(128,IN);
		constructIdentity(128,OUT);
		constructIdentity(128,INOpposite);
		constructIdentity(128,OUTOpposite);
	}
	for(i=0;i<128;i++)
	{
		for(j=0;j<16;j++)
		{
			transformBitsToByte(INOpposite[i]+8*j,INByteOpposite[i]+j);
			transformBitsToByte(OUTOpposite[i]+8*j,OUTByteOpposite[i]+j);
		}
	}	
}

//This function construct the TSR tables of the round 1
static void constructTSRRound1()
{
	int i,j,k,l;
	uint8_t vectorIn[8][1];
	uint8_t vectorOut[128][1];
	uint8_t INStripe[128][8];
	uint8_t Mr[128][8];
	uint8_t temp[128][8];
	for (i=0;i<4;i++)
	{
		for (j=0;j<4;j++)
		{
			stripMatrix(128,128,(4*i+j)*8,(4*i+j)*8+8,IN,INStripe);
			multiplyMatrix(128,128,8,SRMatrix,INStripe,temp);
			multiplyMatrix(128,128,8,LLInvMappings[0],temp,Mr);
			for (k=0;k<256;k++)
			{
				transformByteToBits((uint8_t)k,vectorIn);
				multiplyMatrix(128,8,1,Mr,vectorIn,vectorOut);
				for (l=0;l<16;l++)
				{
					transformBitsToByte(vectorOut+8*l,&(TSRRound1[i][j][k][l]));
				}
			}
		}
	}
}

//This function construct all the remaining TSR tables
static void constructTSR()
{
	int round,i,j,k,l;
	uint8_t vectorIn[8][1];
	uint8_t vectorOut[128][1];
	uint8_t SRStripe[128][32];
	uint8_t OUTStripe[128][32];
	uint8_t RInvStripe1[32][4];
	uint8_t RInvStripe2[32][4];
	uint8_t RInv[32][8];
	uint8_t Mr[128][8];
	uint8_t temp[128][8];
	for (round=2;round<Nr+1;round++)
	{
		for (i=0;i<4;i++)
		{
			for (j=0;j<8;j++)
			{
				stripMatrix(128,128,32*i,32*i+32,SRMatrix,SRStripe);
				stripMatrix(32,32,4*j,4*j+4,RInvMappings[round-2][2*i],RInvStripe1);
				stripMatrix(32,32,4*j,4*j+4,RInvMappings[round-2][2*i+1],RInvStripe2);
				groupMatrix(32,4,4,RInvStripe1,RInvStripe2,RInv);
				multiplyMatrix(128,32,8,SRStripe,RInv,temp);
				multiplyMatrix(128,128,8,LLInvMappings[round-1],temp,Mr);
				for (k=0;k<256;k++)
				{
					transformByteToBits((uint8_t)k,vectorIn);
					multiplyMatrix(128,8,1,Mr,vectorIn,vectorOut);
					for (l=0;l<16;l++)
					{
						transformBitsToByte(vectorOut+8*l,&(TSR[round-2][i][j][k][l]));
					}
				}
			}
		}
	}
	for (i=0;i<4;i++)
	{
		for (j=0;j<8;j++)
		{
			stripMatrix(128,128,32*i,32*i+32,OUT,OUTStripe);
			stripMatrix(32,32,4*j,4*j+4,RInvMappings[Nr-1][2*i],RInvStripe1);
			stripMatrix(32,32,4*j,4*j+4,RInvMappings[Nr-1][2*i+1],RInvStripe2);
			groupMatrix(32,4,4,RInvStripe1,RInvStripe2,RInv);
			multiplyMatrix(128,32,8,OUTStripe,RInv,Mr);
			for (k=0;k<256;k++)
			{
				transformByteToBits((uint8_t)k,vectorIn);
				multiplyMatrix(128,8,1,Mr,vectorIn,vectorOut);
				for (l=0;l<16;l++)
				{
					transformBitsToByte(vectorOut+8*l,&(TSR[round-2][i][j][k][l]));
				}
			}
		}
	}
}

//This function construct all the nTMC tables
static void constructnTMC()
{
	int round,i,j,k,l;
	uint8_t vectorIn[16][1];
	uint8_t vectorTemp16[16][1];
	uint8_t vectorTemp32[32][1];
	uint8_t vectorOut[32][1];
	uint8_t bytesTemp[2];
	uint8_t bytesMixed[4]; //result of MixColumns
	KeyExpansion();
	constructTBox();
	for (round=1;round<Nr;round++)
	{
		for (i=0;i<8;i++)
		{
			for (j=0;j<256;j++)
			{
				for (k=0;k<256;k++)
				{
					transformByteToBits((uint8_t)j,vectorIn);
					transformByteToBits((uint8_t)k,vectorIn+8);
					multiplyMatrix(16,16,1,LMappings[round-1][i],vectorIn,vectorTemp16);
					transformBitsToByte(vectorTemp16,bytesTemp);
					transformBitsToByte(vectorTemp16+8,bytesTemp+1);
					bytesTemp[0] = getTBoxValue(round-1,2*i,bytesTemp[0]);
					bytesTemp[1] = getTBoxValue(round-1,2*i+1,bytesTemp[1]);
					if (i%2==0)
					{
						bytesMixed[0] = xtime(bytesTemp[0])^xtime(bytesTemp[1])^bytesTemp[1];
						bytesMixed[1] = bytesTemp[0]^xtime(bytesTemp[1]);
						bytesMixed[2] = bytesTemp[0]^bytesTemp[1];
						bytesMixed[3] = xtime(bytesTemp[0])^bytesTemp[0]^bytesTemp[1];
					}
					else
					{
						bytesMixed[0] = bytesTemp[0]^bytesTemp[1];
						bytesMixed[1] = xtime(bytesTemp[0])^bytesTemp[0]^bytesTemp[1];
						bytesMixed[2] = xtime(bytesTemp[0])^xtime(bytesTemp[1])^bytesTemp[1];
						bytesMixed[3] = bytesTemp[0]^xtime(bytesTemp[1]);
					}
					transformByteToBits(bytesMixed[0],vectorTemp32);
					transformByteToBits(bytesMixed[1],vectorTemp32+8);
					transformByteToBits(bytesMixed[2],vectorTemp32+16);
					transformByteToBits(bytesMixed[3],vectorTemp32+24);
					multiplyMatrix(32,32,1,RMappings[round-1][i],vectorTemp32,vectorOut);
					for(l=0;l<4;l++)
					{
						transformBitsToByte(vectorOut+8*l,&(nTMC[round-1][i][j][k][l]));
					}
				}
			}
		}
	}
	for (i=0;i<8;i++)
	{
		for (j=0;j<256;j++)
		{
			for (k=0;k<256;k++)
			{
				transformByteToBits((uint8_t)j,vectorIn);
				transformByteToBits((uint8_t)k,vectorIn+8);
				multiplyMatrix(16,16,1,LMappings[Nr-1][i],vectorIn,vectorTemp16);
				transformBitsToByte(vectorTemp16,bytesTemp);
				transformBitsToByte(vectorTemp16+8,bytesTemp+1);
				bytesTemp[0] = getTBoxValue(Nr-1,2*i,bytesTemp[0]);
				bytesTemp[1] = getTBoxValue(Nr-1,2*i+1,bytesTemp[1]);
				if (i%2==0)
				{
					bytesMixed[0] = bytesTemp[0];
					bytesMixed[1] = bytesTemp[1];
					bytesMixed[2] = 0;
					bytesMixed[3] = 0;
				}
				else
				{
					bytesMixed[0] = 0;
					bytesMixed[1] = 0;
					bytesMixed[2] = bytesTemp[0];
					bytesMixed[3] = bytesTemp[1];
				}
				transformByteToBits(bytesMixed[0],vectorTemp32);
				transformByteToBits(bytesMixed[1],vectorTemp32+8);
				transformByteToBits(bytesMixed[2],vectorTemp32+16);
				transformByteToBits(bytesMixed[3],vectorTemp32+24);
				multiplyMatrix(32,32,1,RMappings[Nr-1][i],vectorTemp32,vectorOut);
				for(l=0;l<4;l++)
				{
					transformBitsToByte(vectorOut+8*l,&(nTMC[Nr-1][i][j][k][l]));
				}
			}
		}
	}
}

//This function construct all the TXOR and TXOR3 tables, it just copies the XOR table and XOR3 table in every instance
static void constructTXOR()
{
	int round,nibble,number,i,j;
	for (nibble=0;nibble<32;nibble++)
	{
		for(number=0;number<5;number++)
		{
			for(i=0;i<256;i++)
			{
				TXORRound1[nibble][number][i]=XOR[i];
				for(j=0;j<16;j++)
				{
					TXOR3Round1[nibble][number][i][j]=XOR3[i][j];
				}
			}
		}
	}

	for (round=0;round<Nr;round++)
	{
		for (nibble=0;nibble<32;nibble++)
		{
			for(number=0;number<13;number++)
			{
				for(i=0;i<256;i++)
				{
					TXOR[round][nibble][number][i]=XOR[i];
				}
			}
			for(number=0;number<9;number++)
			{
				for(i=0;i<256;i++)
				{
					for(j=0;j<16;j++)
					{
						TXOR3[round][nibble][number][i][j]=XOR3[i][j];
					}
				}
			}
		}
	}
}

//This function generate a random permutation and its inverse over [0,15]
static void generatePermutation(const int size, uint8_t *permutation, uint8_t *inverse)
{
	int i, j;
	uint8_t temp;
	for (i=0; i<size;i++)
	{
		permutation[i]=i;
	}
	for (i=0; i< size-1;i++)
	{
		j=rand()%(size-i);
		temp=permutation[i];
		permutation[i] = permutation[i+j];
		permutation[i+j] = temp;
	}
	for (i=0;i<size;i++)
	{
		inverse[permutation[i]]=i;
	}
}

//This function generate all the encodings and their inverse
static void generateEncodings()
{
	int i,j;
	for(i=0;i<32;i++)
	{
		if(EXTERNAL_ENCODINGS && ENCODINGS)
		{
			generatePermutation(16,in[i],inputEncodings[i]);
			generatePermutation(16,out[18751-i],outputEncodings[31-i]);
		}
		else
		{
			for(j=0;j<16;j++)
			{
				in[i][j]=j;
				inputEncodings[i][j]=j;
				out[18751-i][j]=j;
				outputEncodings[31-i][j]=j;
			}
		}
	}
	for(i=32;i<18752;i++)
	{
		if(ENCODINGS)
		{
			generatePermutation(16,in[i],out[i-32]); //out[i-32] is the opposite of in[i]
		}
		else
		{
			for(j=0;j<16;j++)
			{
				in[i][j]=j;
				out[18751-i][j]=j;
			}
		}
	}
}

//this function encode a TSR table, it first find the table according its number and then reorder it according to the input encodings and modifies the values according the output encodings
static void encodeTSR(const int tableNumber, int * const indexesIn, int * const indexesOut)
{
	int i,j;
	int round, roundNumber;
	uint8_t temp[256][16];
	if (tableNumber<16)
	{
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				temp[i][j]=	TSRRound1[tableNumber/4][tableNumber%4][in[indexesIn[0]][i&0X0F]^
						((in[indexesIn[1]][(i&0XF0)>>4])<<4)][j];
			}
		}
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				TSRRound1[tableNumber/4][tableNumber%4][i][j]=	out[indexesOut[2*j]][temp[i][j]&0x0F]^
										(out[indexesOut[2*j+1]][(temp[i][j]&0XF0)>>4]<<4);
			}
		}
	}
	else
	{
		round=(tableNumber-16)/32;
		roundNumber=(tableNumber-16)%32;
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				temp[i][j]=	TSR[round][roundNumber/8][roundNumber%8][in[indexesIn[0]][i&0X0F]^
						((in[indexesIn[1]][(i&0XF0)>>4])<<4)][j];
			}
		}
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				TSR[round][roundNumber/8][roundNumber%8][i][j]=	out[indexesOut[2*j]][temp[i][j]&0x0F]^
										(out[indexesOut[2*j+1]][(temp[i][j]&0XF0)>>4]<<4);
			}
		}
	}
}

//this function encode a nTMC table, it first find the table according its number and then reorder it according to the input encodings and modifies the values according the output encodings
static void encodenTMC(const int tableNumber, int * const indexesIn, int * const indexesOut)
{
	int i,j,k,round,roundNumber;
	uint8_t temp[256][256][4];
	round=tableNumber/8;
	roundNumber=tableNumber%8;
	for (i=0;i<256;i++)
	{
		for(j=0;j<256;j++)
		{
			for(k=0;k<4;k++)
			{
				temp[i][j][k]=	nTMC[round][roundNumber][in[indexesIn[0]][i&0X0F]^
						((in[indexesIn[1]][(i&0XF0)>>4])<<4)][in[indexesIn[2]][j&0X0F]^
						((in[indexesIn[3]][(j&0XF0)>>4])<<4)][k];
			}
		}
	}
	for (i=0;i<256;i++)
	{
		for(j=0;j<256;j++)
		{
			for(k=0;k<4;k++)
			{
				nTMC[round][roundNumber][i][j][k]=	out[indexesOut[2*k]][temp[i][j][k]&0x0F]^
									(out[indexesOut[2*k+1]][(temp[i][j][k]&0XF0)>>4]<<4);
			}
		}
	}
}

//this function encode a TXOR table, it first find the table according its number and then reorder it according to the input encodings and modifies the values according the output encodings
static void encodeTXOR(const int tableNumber, int * const indexesIn, const int indexOut)
{
	int round, nibble, localNumber;
	int i;
	uint8_t temp[256];
	if(tableNumber<160)
	{
		nibble = tableNumber/5;
		localNumber = tableNumber%5;
		for(i=0;i<256;i++)
		{
			temp[i] = TXORRound1[nibble][localNumber][in[indexesIn[0]][i&0X0F]^((in[indexesIn[1]][(i&0XF0)>>4])<<4)];
		}
		for(i=0;i<256;i++)
		{
			TXORRound1[nibble][localNumber][i]=out[indexOut][temp[i]];
		}
	}
	else
	{
		round=(tableNumber-160)/416;
		nibble=((tableNumber-160)%416)/13;
		localNumber=((tableNumber-160)%416)%13;
		for(i=0;i<256;i++)
		{
			temp[i] = TXOR[round][nibble][localNumber][in[indexesIn[0]][i&0X0F]^((in[indexesIn[1]][(i&0XF0)>>4])<<4)];
		}
		for(i=0;i<256;i++)
		{
			TXOR[round][nibble][localNumber][i]=out[indexOut][temp[i]];
		}
	}
}

//this function encode a TXOR3 table, it first find the table according its number and then reorder it according to the input encodings and modifies the values according the output encodings
static void encodeTXOR3(const int tableNumber, int * const indexesIn, const int indexOut)
{
	int round, nibble, localNumber;
	int i,j;
	uint8_t temp[256][16];
	if(tableNumber<160)
	{
		nibble = tableNumber/5;
		localNumber = tableNumber%5;
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				temp[i][j] = 	TXOR3Round1[nibble][localNumber][in[indexesIn[0]][i&0X0F]^
						((in[indexesIn[1]][(i&0XF0)>>4])<<4)][in[indexesIn[2]][j]];
			}
		}
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				TXOR3Round1[nibble][localNumber][i][j]=out[indexOut][temp[i][j]];
			}
		}
	}
	else
	{
		round=(tableNumber-160)/288;
		nibble=((tableNumber-160)%288)/9;
		localNumber=((tableNumber-160)%288)%9;
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				temp[i][j] = 	TXOR3[round][nibble][localNumber][in[indexesIn[0]][i&0X0F]^
						((in[indexesIn[1]][(i&0XF0)>>4])<<4)][in[indexesIn[2]][j]];
			}
		}
		for(i=0;i<256;i++)
		{
			for(j=0;j<16;j++)
			{
				TXOR3[round][nibble][localNumber][i][j]=out[indexOut][temp[i][j]];
			}
		}
	}
}

//This function encodes all the table by calling the previous functions. It is important to follow the flow of bytes in the implementation so that the inverse encodings are paired from one output
//to the next input and cancel each other

static void encodeEverything()
{
	int TSRNumber,nTMCNumber,TXORNumber,TXOR3Number;
	int TSRInIndexes[2],TSROutIndexes[32],nTMCInIndexes[4],nTMCOutIndexes[8],TXORInIndexes[2],TXOR3InIndexes[3],TXOROutIndex,TXOR3OutIndex;
	int round,i,j,k,n,l;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			TSRNumber=i+4*j;
			for(k=0;k<2;k++)
			{
				TSRInIndexes[k]=2*(i+4*j)+k;
			}
			for(k=0;k<32;k++)
			{
				TSROutIndexes[k]=32*(i+4*j)+k;
			}
			encodeTSR(TSRNumber,TSRInIndexes,TSROutIndexes);
		}
	}
	for(n=0;n<32;n++)
	{
		for(l=0;l<4;l++)
		{
			TXOR3Number=n*5+l;
			for(k=0;k<3;k++)
			{
				TXOR3InIndexes[k]=32+(l*3+k)*32+n;
			}
			TXOR3OutIndex=512+32*l+n;
			encodeTXOR3(TXOR3Number,TXOR3InIndexes,TXOR3OutIndex);
		}
		for(l=0;l<5;l++)
		{
			TXORNumber=n*5+l;
			for(k=0;k<2;k++)
			{
				TXORInIndexes[k]=32+(12+2*l+k)*32+n;
			}
			TXOROutIndex=512+(4+l)*32+n;
			encodeTXOR(TXORNumber,TXORInIndexes,TXOROutIndex);
		}
		TXOR3Number=n*5+4;
		for(k=0;k<3;k++)
		{
			TXOR3InIndexes[k]=736+32*k+n;
		}
		TXOR3OutIndex=800+n;
		encodeTXOR3(TXOR3Number,TXOR3InIndexes,TXOR3OutIndex);
	}
	for(round=0;round<Nr;round++)
	{
		for(i=0;i<8;i++)
		{
			nTMCNumber=8*round+i;
			for(k=0;k<4;k++)
			{
				nTMCInIndexes[k]=832+1792*round+4*i+k;
			}
			for(k=0;k<8;k++)
			{
				nTMCOutIndexes[k]=832+1792*round+8*i+k;
			}
			encodenTMC(nTMCNumber,nTMCInIndexes,nTMCOutIndexes);
		}
		for(i=0;i<4;i++)
		{
			for(j=0;j<8;j++)
			{
				TSRNumber=16+32*round+8*i+j;
				for(k=0;k<2;k++)
				{
					TSRInIndexes[k]=864+1792*round+8*(2*i+k)+j;
				}
				for(k=0;k<32;k++)
				{
					TSROutIndexes[k]=896+1792*round+32*(8*i+j)+k;
				}
				encodeTSR(TSRNumber,TSRInIndexes,TSROutIndexes);
			}
		}
		for(n=0;n<32;n++)
		{
			for(l=0;l<8;l++)
			{
				TXOR3Number=160+288*round+n*9+l;
				for(k=0;k<3;k++)
				{
					TXOR3InIndexes[k]=928+1792*round+(l*3+k)*32+n;
				}
				TXOR3OutIndex=1920+1792*round+32*l+n;
				encodeTXOR3(TXOR3Number,TXOR3InIndexes,TXOR3OutIndex);
			}
			for(l=0;l<13;l++)
			{
				TXORNumber=160+416*round+n*13+l;
				for(k=0;k<2;k++)
				{
					TXORInIndexes[k]=1696+1792*round+(2*l+k)*32+n;
				}
				TXOROutIndex=1920+1792*round+(8+l)*32+n;
				encodeTXOR(TXORNumber,TXORInIndexes,TXOROutIndex);
			}
			TXOR3Number=160+288*round+n*9+8;
			for(k=0;k<3;k++)
			{
				TXOR3InIndexes[k]=2528+1792*round+32*k+n;
			}
			TXOR3OutIndex=2592+1792*round+n;
			encodeTXOR3(TXOR3Number,TXOR3InIndexes,TXOR3OutIndex);
		}
	}
}


//print all the tables into the file table.h as a form of global variable
static void printEverything(FILE* table)
{
	int i,j,k,l,m;
	fprintf(table,"#include <stdint.h>\nuint8_t TSRRound1[4][4][256][16]={"); 
	for(i=0;i<4;i++)
	{
		fprintf(table,"{");
		for(j=0;j<4;j++)
		{
			fprintf(table,"{");
			for(k=0;k<256;k++)
			{
				fprintf(table,"{");
				for(l=0;l<16;l++)
				{
					fprintf(table,"%i",TSRRound1[i][j][k][l]);
					if(l<15)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<255)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<3)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if(i<3)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t TSR[10][4][8][256][16]={");
	for(i=0;i<Nr;i++)
	{
		fprintf(table,"{");
		for(j=0;j<4;j++)
		{
			fprintf(table,"{");
			for(k=0;k<8;k++)
			{
				fprintf(table,"{");
				for(l=0;l<256;l++)
				{
					fprintf(table,"{");
					for(m=0;m<16;m++)
					{
						fprintf(table,"%i",TSR[i][j][k][l][m]);
						if(m<15)
						{
							fprintf(table,",");
						}
					}
					fprintf(table,"}");
					if(l<255)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<8)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<3)
			{
				fprintf(table,",");
			}
			
		}
		fprintf(table,"}");
		if(i<Nr-1)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t nTMC[10][8][256][256][4]={");
	for(i=0;i<Nr;i++)
	{
		fprintf(table,"{");
		for(j=0;j<8;j++)
		{
			fprintf(table,"{");
			for(k=0;k<256;k++)
			{
				fprintf(table,"{");
				for(l=0;l<256;l++)
				{
					fprintf(table,"{");
					for(m=0;m<4;m++)
					{
						fprintf(table,"%i",nTMC[i][j][k][l][m]);
						if(m<3)
						{
							fprintf(table,",");
						}
					}
					fprintf(table,"}");
					if(l<255)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<255)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<7)
			{
				fprintf(table,",");
			}
			
		}
		fprintf(table,"}");
		if(i<Nr-1)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t TXORRound1[32][5][256]={");
	for(i=0;i<32;i++)
	{
		fprintf(table,"{");
		for(j=0;j<5;j++)
		{
			fprintf(table,"{");
			for(k=0;k<256;k++)
			{
				fprintf(table,"%i",TXORRound1[i][j][k]);
				if(k<255)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<4)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if(i<31)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t TXOR3Round1[32][5][256][16]={");
	for(i=0;i<32;i++)
	{
		fprintf(table,"{");
		for(j=0;j<5;j++)
		{
			fprintf(table,"{");
			for(k=0;k<256;k++)
			{
				fprintf(table,"{");
				for(l=0;l<16;l++)
				{
					fprintf(table,"%i",TXOR3Round1[i][j][k][l]);
					if(l<15)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<255)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<4)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if(i<31)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t TXOR[10][32][13][256]={");
	for(i=0;i<Nr;i++)
	{
		fprintf(table,"{");
		for(j=0;j<32;j++)
		{
			fprintf(table,"{");
			for(k=0;k<13;k++)
			{
				fprintf(table,"{");
				for(l=0;l<256;l++)
				{
					fprintf(table,"%i",TXOR[i][j][k][l]);
					if(l<255)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<12)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<31)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if(i<Nr-1)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t TXOR3[10][32][9][256][16]={");
	for(i=0;i<Nr;i++)
	{
		fprintf(table,"{");
		for(j=0;j<32;j++)
		{
			fprintf(table,"{");
			for(k=0;k<9;k++)
			{
				fprintf(table,"{");
				for(l=0;l<256;l++)
				{
					fprintf(table,"{");
					for(m=0;m<16;m++)
					{
						fprintf(table,"%i",TXOR3[i][j][k][l][m]);
						if(m<15)
						{
							fprintf(table,",");
						}
					}
					fprintf(table,"}");
					if(l<255)
					{
						fprintf(table,",");
					}
				}
				fprintf(table,"}");
				if(k<8)
				{
					fprintf(table,",");
				}
			}
			fprintf(table,"}");
			if(j<31)
			{
				fprintf(table,",");
			}
			
		}
		fprintf(table,"}");
		if(i<Nr-1)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");
	
	fprintf(table,"uint8_t INOpposite[128][16] = {");	
	for (i=0;i<128;i++)
	{
		fprintf(table,"{");
		for (j=0;j<16;j++)
		{
			fprintf(table,"%i",INByteOpposite[i][j]);
			if (j<15)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if (i<127)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t OUTOpposite[128][16] = {");	
	for (i=0;i<128;i++)
	{
		fprintf(table,"{");
		for (j=0;j<16;j++)
		{
			fprintf(table,"%i",OUTByteOpposite[i][j]);
			if (j<15)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if (i<127)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t inputEncodings[32][16] = {");	
	for (i=0;i<32;i++)
	{
		fprintf(table,"{");
		for (j=0;j<16;j++)
		{
			fprintf(table,"%i",inputEncodings[i][j]);
			if (j<15)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if (i<31)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");

	fprintf(table,"uint8_t outputEncodings[32][16] = {");	
	for (i=0;i<32;i++)
	{
		fprintf(table,"{");
		for (j=0;j<16;j++)
		{
			fprintf(table,"%i",outputEncodings[i][j]);
			if (j<15)
			{
				fprintf(table,",");
			}
		}
		fprintf(table,"}");
		if (i<31)
		{
			fprintf(table,",");
		}
	}
	fprintf(table,"};\n");
}

int main(int argc, char* argv[])
{
	int i,j,k,l,round;
	uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	FILE *tableFile;
	uint8_t in[16];
	char* ptr;

	//process the input, if the format is wrong a standard key is used

	if (argc != 17)
	{
		printf("Input is not 16 bytes long, default key used\n");
		Key = key;
	}
	else
	{
		for(i=0;i<16;i++)
		{
			in[i] = (char) strtol(argv[i+1],&ptr,16);
		}
		Key = in;
	}
	
	srand(time(NULL)); //better pseudo-random number generator possible

	constructSRMatrix();
	constructXor();
	constructLMappings();
	constructRMappings();
	constructExternalEncodings();
	generateEncodings();
	constructTSRRound1();
	constructTSR();
	printf("TSR constructed\n");
	constructnTMC();
	printf("nTMC constructed\n");
	constructTXOR();
	encodeEverything();
	tableFile=fopen("table.h","w+");
	if(tableFile!=NULL)
	{	
		printEverything(tableFile);
		fclose(tableFile);
	}
	return 0;
}

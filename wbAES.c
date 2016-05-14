#include <stdint.h>
#include <stdio.h>
#include "table.h"

//This program realises the AES encryption using the white-box implementation of Luo-Lai-You. It first process the input, encode it performs the encryption by lookup tables and decode the output.
//The table and external encodings to use must be present in table.h as the result of executing the program compiled from the generator.

// The number of rounds in AES Cipher.
#define Nr 10

//parity of byte, used to perform the matrix multiplication on bits using bytes
static uint8_t parity(uint8_t byte)
{
	byte ^= byte >> 4;
	byte ^= byte >> 2;
	byte ^= byte >> 1;
	return byte & 1;
}

//transform 8 bits in 1 byte
static void transformBitsToByte(uint8_t (* const bits)[1], uint8_t *byte)
{
	int i;
	*byte=0;
	for (i=0;i<8;i++)
	{
		*byte+=(*bits)[i]<<i;
	}
}

int main(int argc, char* argv[])
{
	int i,j,k,l,round;
	uint8_t input[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	uint8_t inputEncodedBits[128] = {0};
	uint8_t outputDecodedBits[128] = {0};
	uint8_t inputEncoded[16] = {0};
	uint8_t outputDecoded[16] = {0};
	uint8_t outputStage1_1[16][16];
	uint8_t intermediateStage2_1[12][16];
	uint8_t intermediateStage2_2[6][16];
	uint8_t intermediateStage2_3[3][16];
	uint8_t outputStage2[16];
	uint8_t outputStage3[8][4];
	uint8_t inputStage1_2[4][8];
	uint8_t outputStage1_2[32][16];
	
	char* ptr;

	//process the input

	if (argc != 17)
	{
		printf("Input is not 16 bytes long\n");
		return 0;
	}
	else
	{
		for(i=0;i<16;i++)
		{
			input[i] = (char) strtol(argv[i+1],&ptr,16);
		}
	}
	
	//encode the input using matrix multiplication

	for(i=0;i<128;i++)
	{
		inputEncodedBits[i] = 0;
		for (j=0;j<16;j++)
		{
			inputEncodedBits[i] ^= input[j]&INOpposite[i][j];
		}
		inputEncodedBits[i]=parity(inputEncodedBits[i]);
	}
	
	for(i=0;i<16;i++)
	{
		transformBitsToByte(inputEncodedBits+8*i,inputEncoded+i);
		inputEncoded[i] = inputEncodings[2*i][inputEncoded[i]&0x0F]^(inputEncodings[2*i+1][(inputEncoded[i]&0xF0)>>4])<<4;
	}

	//first stage of the round1

	for (i=0;i<4;i++)
	{
		for (j=0;j<4;j++)
		{
			for (k=0;k<16;k++)
			{
				outputStage1_1[4*i+j][k] = TSRRound1[i][j][inputEncoded[4*i+j]][k];
			}
		}
	}
	
	//reduction using XORs

	for(k=0;k<16;k++)
	{
		intermediateStage2_2[0][k]=(TXOR3Round1[2*k][0][((outputStage1_1[0][k])&0X0F)^(((outputStage1_1[1][k])&0X0F)<<4)][outputStage1_1[2][k]&0X0F])^((TXOR3Round1[2*k+1][0][(((outputStage1_1[0][k])&0XF0)>>4)^((outputStage1_1[1][k])&0XF0)][(outputStage1_1[2][k]&0XF0)>>4])<<4);
		intermediateStage2_2[1][k]=(TXOR3Round1[2*k][1][((outputStage1_1[3][k])&0X0F)^(((outputStage1_1[4][k])&0X0F)<<4)][outputStage1_1[5][k]&0X0F])^((TXOR3Round1[2*k+1][1][(((outputStage1_1[3][k])&0XF0)>>4)^((outputStage1_1[4][k])&0XF0)][(outputStage1_1[5][k]&0XF0)>>4])<<4);
		intermediateStage2_2[2][k]=(TXOR3Round1[2*k][2][((outputStage1_1[6][k])&0X0F)^(((outputStage1_1[7][k])&0X0F)<<4)][outputStage1_1[8][k]&0X0F])^((TXOR3Round1[2*k+1][2][(((outputStage1_1[6][k])&0XF0)>>4)^((outputStage1_1[7][k])&0XF0)][(outputStage1_1[8][k]&0XF0)>>4])<<4);
		intermediateStage2_2[3][k]=(TXOR3Round1[2*k][3][((outputStage1_1[9][k])&0X0F)^(((outputStage1_1[10][k])&0X0F)<<4)][outputStage1_1[11][k]&0X0F])^((TXOR3Round1[2*k+1][3][(((outputStage1_1[9][k])&0XF0)>>4)^((outputStage1_1[10][k])&0XF0)][(outputStage1_1[11][k]&0XF0)>>4])<<4);
		intermediateStage2_2[4][k]=(TXORRound1[2*k][0][((outputStage1_1[12][k])&0X0F)^(((outputStage1_1[13][k])&0X0F)<<4)])^((TXORRound1[2*k+1][0][(((outputStage1_1[12][k])&0XF0)>>4)^((outputStage1_1[13][k])&0XF0)])<<4);
		intermediateStage2_2[5][k]=(TXORRound1[2*k][1][((outputStage1_1[14][k])&0X0F)^(((outputStage1_1[15][k])&0X0F)<<4)])^((TXORRound1[2*k+1][1][(((outputStage1_1[14][k])&0XF0)>>4)^((outputStage1_1[15][k])&0XF0)])<<4);
	}

	for(k=0;k<16;k++)
	{
		intermediateStage2_3[0][k]=(TXORRound1[2*k][2][((intermediateStage2_2[0][k])&0X0F)^(((intermediateStage2_2[1][k])&0X0F)<<4)])^((TXORRound1[2*k+1][2][(((intermediateStage2_2[0][k])&0XF0)>>4)^((intermediateStage2_2[1][k])&0XF0)])<<4);
		intermediateStage2_3[1][k]=(TXORRound1[2*k][3][((intermediateStage2_2[2][k])&0X0F)^(((intermediateStage2_2[3][k])&0X0F)<<4)])^((TXORRound1[2*k+1][3][(((intermediateStage2_2[2][k])&0XF0)>>4)^((intermediateStage2_2[3][k])&0XF0)])<<4);
		intermediateStage2_3[2][k]=(TXORRound1[2*k][4][((intermediateStage2_2[4][k])&0X0F)^(((intermediateStage2_2[5][k])&0X0F)<<4)])^((TXORRound1[2*k+1][4][(((intermediateStage2_2[4][k])&0XF0)>>4)^((intermediateStage2_2[5][k])&0XF0)])<<4);
	}
	
	for(k=0;k<16;k++)
	{
		outputStage2[k]=(TXOR3Round1[2*k][4][((intermediateStage2_3[0][k])&0X0F)^(((intermediateStage2_3[1][k])&0X0F)<<4)][intermediateStage2_3[2][k]&0X0F])^((TXOR3Round1[2*k+1][4][(((intermediateStage2_3[0][k])&0XF0)>>4)^((intermediateStage2_3[1][k])&0XF0)][(intermediateStage2_3[2][k]&0XF0)>>4])<<4);
	}

	for(round=0;round<Nr;round++)
	{

		for(i=0;i<8;i++)
		{
			for(j=0;j<4;j++)
			{
				outputStage3[i][j] = nTMC[round][i][outputStage2[2*i]][outputStage2[2*i+1]][j];
			}
		}

		//preparation of the input of the TSR tables from the output of nTMC
		
		for (i=0;i<4;i++)
		{
			for (j=0;j<8;j++)
			{
				inputStage1_2[i][j] = 0;
				inputStage1_2[i][j] ^= (outputStage3[2*i][j/2]&(0x0F<<(4*(j%2))))>>(4*(j%2));
				inputStage1_2[i][j] ^= (outputStage3[2*i+1][j/2]&(0x0F<<(4*(j%2))))<<(4*((j+1)%2)); 
			}
		}


		for (i=0;i<4;i++)
		{
			for (j=0;j<8;j++)
			{
				for (k=0;k<16;k++)
				{
					outputStage1_2[8*i+j][k] = TSR[round][i][j][inputStage1_2[i][j]][k];
				}
			}
		}
		
		//reduction using XORs
		
		for(k=0;k<16;k++)
		{
			intermediateStage2_1[0][k]=(TXOR3[round][2*k][0][((outputStage1_2[0][k])&0X0F)^(((outputStage1_2[1][k])&0X0F)<<4)][outputStage1_2[2][k]&0X0F])^((TXOR3[round][2*k+1][0][(((outputStage1_2[0][k])&0XF0)>>4)^((outputStage1_2[1][k])&0XF0)][(outputStage1_2[2][k]&0XF0)>>4])<<4);
			intermediateStage2_1[1][k]=(TXOR3[round][2*k][1][((outputStage1_2[3][k])&0X0F)^(((outputStage1_2[4][k])&0X0F)<<4)][outputStage1_2[5][k]&0X0F])^((TXOR3[round][2*k+1][1][(((outputStage1_2[3][k])&0XF0)>>4)^((outputStage1_2[4][k])&0XF0)][(outputStage1_2[5][k]&0XF0)>>4])<<4);
			intermediateStage2_1[2][k]=(TXOR3[round][2*k][2][((outputStage1_2[6][k])&0X0F)^(((outputStage1_2[7][k])&0X0F)<<4)][outputStage1_2[8][k]&0X0F])^((TXOR3[round][2*k+1][2][(((outputStage1_2[6][k])&0XF0)>>4)^((outputStage1_2[7][k])&0XF0)][(outputStage1_2[8][k]&0XF0)>>4])<<4);
			intermediateStage2_1[3][k]=(TXOR3[round][2*k][3][((outputStage1_2[9][k])&0X0F)^(((outputStage1_2[10][k])&0X0F)<<4)][outputStage1_2[11][k]&0X0F])^((TXOR3[round][2*k+1][3][(((outputStage1_2[9][k])&0XF0)>>4)^((outputStage1_2[10][k])&0XF0)][(outputStage1_2[11][k]&0XF0)>>4])<<4);
			intermediateStage2_1[4][k]=(TXOR3[round][2*k][4][((outputStage1_2[12][k])&0X0F)^(((outputStage1_2[13][k])&0X0F)<<4)][outputStage1_2[14][k]&0X0F])^((TXOR3[round][2*k+1][4][(((outputStage1_2[12][k])&0XF0)>>4)^((outputStage1_2[13][k])&0XF0)][(outputStage1_2[14][k]&0XF0)>>4])<<4);
			intermediateStage2_1[5][k]=(TXOR3[round][2*k][5][((outputStage1_2[15][k])&0X0F)^(((outputStage1_2[16][k])&0X0F)<<4)][outputStage1_2[17][k]&0X0F])^((TXOR3[round][2*k+1][5][(((outputStage1_2[15][k])&0XF0)>>4)^((outputStage1_2[16][k])&0XF0)][(outputStage1_2[17][k]&0XF0)>>4])<<4);
			intermediateStage2_1[6][k]=(TXOR3[round][2*k][6][((outputStage1_2[18][k])&0X0F)^(((outputStage1_2[19][k])&0X0F)<<4)][outputStage1_2[20][k]&0X0F])^((TXOR3[round][2*k+1][6][(((outputStage1_2[18][k])&0XF0)>>4)^((outputStage1_2[19][k])&0XF0)][(outputStage1_2[20][k]&0XF0)>>4])<<4);
			intermediateStage2_1[7][k]=(TXOR3[round][2*k][7][((outputStage1_2[21][k])&0X0F)^(((outputStage1_2[22][k])&0X0F)<<4)][outputStage1_2[23][k]&0X0F])^((TXOR3[round][2*k+1][7][(((outputStage1_2[21][k])&0XF0)>>4)^((outputStage1_2[22][k])&0XF0)][(outputStage1_2[23][k]&0XF0)>>4])<<4);
			intermediateStage2_1[8][k]=(TXOR[round][2*k][0][((outputStage1_2[24][k])&0X0F)^(((outputStage1_2[25][k])&0X0F)<<4)])^((TXOR[round][2*k+1][0][(((outputStage1_2[24][k])&0XF0)>>4)^((outputStage1_2[25][k])&0XF0)])<<4);
			intermediateStage2_1[9][k]=(TXOR[round][2*k][1][((outputStage1_2[26][k])&0X0F)^(((outputStage1_2[27][k])&0X0F)<<4)])^((TXOR[round][2*k+1][1][(((outputStage1_2[26][k])&0XF0)>>4)^((outputStage1_2[27][k])&0XF0)])<<4);
			intermediateStage2_1[10][k]=(TXOR[round][2*k][2][((outputStage1_2[28][k])&0X0F)^(((outputStage1_2[29][k])&0X0F)<<4)])^((TXOR[round][2*k+1][2][(((outputStage1_2[28][k])&0XF0)>>4)^((outputStage1_2[29][k])&0XF0)])<<4);
			intermediateStage2_1[11][k]=(TXOR[round][2*k][3][((outputStage1_2[30][k])&0X0F)^(((outputStage1_2[31][k])&0X0F)<<4)])^((TXOR[round][2*k+1][3][(((outputStage1_2[30][k])&0XF0)>>4)^((outputStage1_2[31][k])&0XF0)])<<4);
		}
		
		for(k=0;k<16;k++)
		{
			intermediateStage2_2[0][k]=(TXOR[round][2*k][4][((intermediateStage2_1[0][k])&0X0F)^(((intermediateStage2_1[1][k])&0X0F)<<4)])^((TXOR[round][2*k+1][4][(((intermediateStage2_1[0][k])&0XF0)>>4)^((intermediateStage2_1[1][k])&0XF0)])<<4);
			intermediateStage2_2[1][k]=(TXOR[round][2*k][5][((intermediateStage2_1[2][k])&0X0F)^(((intermediateStage2_1[3][k])&0X0F)<<4)])^((TXOR[round][2*k+1][5][(((intermediateStage2_1[2][k])&0XF0)>>4)^((intermediateStage2_1[3][k])&0XF0)])<<4);
			intermediateStage2_2[2][k]=(TXOR[round][2*k][6][((intermediateStage2_1[4][k])&0X0F)^(((intermediateStage2_1[5][k])&0X0F)<<4)])^((TXOR[round][2*k+1][6][(((intermediateStage2_1[4][k])&0XF0)>>4)^((intermediateStage2_1[5][k])&0XF0)])<<4);
			intermediateStage2_2[3][k]=(TXOR[round][2*k][7][((intermediateStage2_1[6][k])&0X0F)^(((intermediateStage2_1[7][k])&0X0F)<<4)])^((TXOR[round][2*k+1][7][(((intermediateStage2_1[6][k])&0XF0)>>4)^((intermediateStage2_1[7][k])&0XF0)])<<4);
			intermediateStage2_2[4][k]=(TXOR[round][2*k][8][((intermediateStage2_1[8][k])&0X0F)^(((intermediateStage2_1[9][k])&0X0F)<<4)])^((TXOR[round][2*k+1][8][(((intermediateStage2_1[8][k])&0XF0)>>4)^((intermediateStage2_1[9][k])&0XF0)])<<4);
			intermediateStage2_2[5][k]=(TXOR[round][2*k][9][((intermediateStage2_1[10][k])&0X0F)^(((intermediateStage2_1[11][k])&0X0F)<<4)])^((TXOR[round][2*k+1][9][(((intermediateStage2_1[10][k])&0XF0)>>4)^((intermediateStage2_1[11][k])&0XF0)])<<4);
		}

		for(k=0;k<16;k++)
		{
			intermediateStage2_3[0][k]=(TXOR[round][2*k][10][((intermediateStage2_2[0][k])&0X0F)^(((intermediateStage2_2[1][k])&0X0F)<<4)])^((TXOR[round][2*k+1][10][(((intermediateStage2_2[0][k])&0XF0)>>4)^((intermediateStage2_2[1][k])&0XF0)])<<4);
			intermediateStage2_3[1][k]=(TXOR[round][2*k][11][((intermediateStage2_2[2][k])&0X0F)^(((intermediateStage2_2[3][k])&0X0F)<<4)])^((TXOR[round][2*k+1][11][(((intermediateStage2_2[2][k])&0XF0)>>4)^((intermediateStage2_2[3][k])&0XF0)])<<4);
			intermediateStage2_3[2][k]=(TXOR[round][2*k][12][((intermediateStage2_2[4][k])&0X0F)^(((intermediateStage2_2[5][k])&0X0F)<<4)])^((TXOR[round][2*k+1][12][(((intermediateStage2_2[4][k])&0XF0)>>4)^((intermediateStage2_2[5][k])&0XF0)])<<4);
		}
	
		for(k=0;k<16;k++)
		{
			outputStage2[k]=(TXOR3[round][2*k][8][((intermediateStage2_3[0][k])&0X0F)^(((intermediateStage2_3[1][k])&0X0F)<<4)][intermediateStage2_3[2][k]&0X0F])^((TXOR3[round][2*k+1][8][(((intermediateStage2_3[0][k])&0XF0)>>4)^((intermediateStage2_3[1][k])&0XF0)][(intermediateStage2_3[2][k]&0XF0)>>4])<<4);
		
		}

		//if it is the last round, decode the output and print it to the screen

		if (round==Nr-1)
		{
			for(i=0;i<16;i++)
			{
				outputStage2[i] = outputEncodings[2*i][outputStage2[i]&0x0F]^(outputEncodings[2*i+1][(outputStage2[i]&0xF0)>>4])<<4;
			}
			for(i=0;i<128;i++)
			{
				outputDecodedBits[i] = 0;
				for (j=0;j<16;j++)
				{
					outputDecodedBits[i] ^= outputStage2[j]&OUTOpposite[i][j];
				}
				outputDecodedBits[i]=parity(outputDecodedBits[i]);
			}

			for(i=0;i<16;i++)
			{
				transformBitsToByte(outputDecodedBits+8*i,outputDecoded+i);
				printf("%02X",outputDecoded[i]);
			}
		}
	}
	printf("\n");

	return 0;
}

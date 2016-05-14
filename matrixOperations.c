#include <stdint.h>

//For all these functions it is really important that the sizes of the matrices involved match the dimensions passed to the functions because there is no check:
//Wrong size would give wrong results if not corrupting other variables or resulting in attempting unallowed memory operations !

//This function fills the matrix with coefficients of the identity matrix
void constructIdentity(const int size, uint8_t (*matrix)[size])
{
	int i,j;
	for (i=0;i<size;i++)
	{
		for (j=0;j<size;j++)
		{
			if(j==i)
			{
				(*matrix)[i*size+j]=1;
			}
			else
			{
				(*matrix)[i*size+j]=0;
			}
		}
	}
}

//This function puts in result the columns of matrix between the column "from" and "to-1"
void stripMatrix(const int lines, const int columns, const int from, const int to, uint8_t (* const matrix)[columns], uint8_t (* result)[from-to])
{
	int i,j;
	for (i=0;i<lines;i++)
	{
		for (j=from;j<to;j++)
		{
			(*result)[i*(to-from)+(j-from)]=(*matrix)[i*columns+j];
		}
	}
}

//This function concatenates the columns of matrix1 and matrix2 into result
void groupMatrix(const int lines, const int columns1, const int columns2, uint8_t (* const matrix1)[columns1], uint8_t (* const matrix2)[columns2], uint8_t (* result)[columns1+columns2])
{
	int i,j;
	for (i=0;i<lines;i++)
	{
		for (j=0;j<columns1;j++)
		{
			(*result)[i*(columns1+columns2)+j] = (*matrix1)[i*columns1+j];
		}
		for (j=0;j<columns2;j++)
		{
			(*result)[i*(columns1+columns2)+j+columns1] = (*matrix2)[i*columns1+j];
		}
	}
}

//This function multiply two matrices and return the result (it is possible to use it for vector multiplication if vector are defined as a table of tables of size 1 to avoid types warning)
void multiplyMatrix(const int lines1, const int columns1, const int columns2, uint8_t (* const matrix1)[columns1], uint8_t (* const matrix2)[columns2], uint8_t (*result)[columns2]) //sizes must be good !
{
	int i, j, k;
	for (i=0;i<lines1;i++)
	{
		for (j=0;j<columns2;j++)
		{
			(*result)[i*columns2+j] = 0;
			for (k=0;k<columns1;k++)
			{
				(*result)[i*columns2+j]^=(*matrix1)[i*columns1+k]*(*matrix2)[k*columns2+j];
			}
		}
	}
}

//This function copy matrix into copy
static void copyMatrix(const int lines, const int columns, uint8_t (* const matrix)[columns], uint8_t (* copy)[columns])
{
	int i,j;
	for(i=0;i<lines;i++)
	{
		for(j=0;j<columns;j++)
		{
			(*copy)[i*columns+j]=(*matrix)[i*columns+j];
		}
	}
}

//This function swap two rows of the matrix, it is used for gaussian elimination
static void swapRows(const int lines, const int columns, const int row1, const int row2, uint8_t (* matrix)[columns])
{
	int i;
	uint8_t temp;
	for(i=0;i<columns;i++)
	{
		temp = (*matrix)[row1*columns+i];
		(*matrix)[row1*columns+i] = (*matrix)[row2*columns+i];
		(*matrix)[row2*columns+i] = temp;
	}
}

//This function adds two lines of the matrix (in the sense of GF(2):XOR), it is used for gaussian elimination
static void addLines(const int lines, const int columns, const int row1, const int row2, uint8_t (* matrix)[columns])
{
	int i;
	for(i=0;i<columns;i++)
	{
		(*matrix)[row2*columns+i]^=(*matrix)[row1*columns+i];
	}
}

//This function invert the matrix in result, CAUTION: matrix gets changed in the operation
static int invertMatrix(const int size, uint8_t (* matrix)[size], uint8_t (* result)[size])
{
	int i,j,k = 0,r = -1;
	constructIdentity(size,result);
	for (j=0;j<size;j++)
	{
		k = -1;
		for(i=j;i<size&&k==-1;i++)
		{
			if((*matrix)[i*size+j]==1)
			{
				k = i;
			}
		}
		if(k==-1)
		{
			return 0;
		}
		r++;
		swapRows(size,size,r,k,matrix);
		swapRows(size,size,r,k,result);
		for (i=0;i<size;i++)
		{
			if(i!=r && (*matrix)[i*size+j]!=0)
			{
				addLines(size,size,r,i,matrix);
				addLines(size,size,r,i,result);
			}
		}
	}
	return 1;
}

//This function generate a pair of matices that are inverse to each other
void generateInvertibleMatrix(uint8_t size, uint8_t (* matrix)[size], uint8_t (* invert)[size])
{
	int i,j,invertible=0;
	uint8_t copy[size][size];
	while(!invertible)
	{
		for(i=0;i<size;i++)
		{
			for(j=0;j<size;j++)
			{
				(*matrix)[i*size+j]=rand()%2;
				copy[i][j]=(*matrix)[i*size+j];
			}
		}
		invertible = invertMatrix(size,copy,invert);
	}
}

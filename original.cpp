#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <cstdlib>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <time.h>

#include <pthread.h>

#define null 0

int bitsize = 0;


struct tensor{
	double var;
	struct tensor *p;
}Head,*Tail;

struct CipherSet{
	LweSample *a;
	LweSample *b;
	int minbit;
	const TFheGateBootstrappingCloudKeySet* EK;
};
struct MulInitSet{
	LweSample *C;
	LweSample *a;
	LweSample *b;
	int ind;
	const TFheGateBootstrappingCloudKeySet* EK;
};
struct CalcSet{
	LweSample *r;
	LweSample *a;
	LweSample *b;
	LweSample *c;
	const TFheGateBootstrappingCloudKeySet* EK;
};
TFheGateBootstrappingSecretKeySet* testkey;
int V = 0;
void *thread_and(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
	bootsAND(input->r,input->a,input->b,input->EK);       

        pthread_exit((void *)input->r);	
}
void *thread_xor(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
        bootsXOR(input->r,input->a,input->b,input->EK);

        pthread_exit((void *)input->r);
}
void *thread_mux(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
	bootsMUX(input->r,input->a,input->b,input->c,input->EK);
	
        pthread_exit((void *)input->r);
}
LweSample* CipherCmp(LweSample *a,LweSample *b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *Tmp = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext(EK->params);

	bootsCONSTANT(Result,0,EK);

	for(int i = 0 ; i < bitsize ; i++)
	{
		bootsXOR(Tmp,&a[i],&b[i],EK);
		bootsOR(Result,Result,Tmp,EK);
	}
	bootsNOT(Result,Result,EK);	
	return Result;
}
LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
	
	pthread_t thread[2];
	struct CalcSet *in[2];

	for(int i= bitsize-1 ; i >= 0 ; i--)
	{
		if(i == bitsize-1)
		{
			/*
			for(int num =0 ; num<2; num++)	in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			in[0]->r = carry;
			in[0]->a = &a[i];
			in[0]->b = &b[i];
			in[0]->EK= EK;

			in[1]->r = &Result[i];
			in[1]->a = &a[i];
			in[1]->b = &b[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_and,(void*)in[0]); // Function for getting carry... 
			pthread_create(&thread[1],NULL,&thread_xor,(void*)in[1]); // Function for getting bit...
			
			pthread_join(thread[0],(void **)&carry);
			pthread_join(thread[1],(void **)&Result[i]);*/
			bootsAND(carry,&a[i],&b[i],EK);
			bootsXOR(&Result[i],&a[i],&b[i],EK);
		}
		else
		{
			/*
                        for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));
*/
			LweSample *b1;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsXOR(b1,&a[i],&b[i],EK);
		/*	
			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsCOPY(b2,carry,EK);			

			in[0]->r = &Result[i];
			in[0]->a = b1;
			in[0]->b = b2;
			in[0]->EK= EK;

			in[1]->r = carry;
			in[1]->a = b1;
			in[1]->b = b2;
			in[1]->c = &a[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
			pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

			pthread_join(thread[0],(void **)&b1);
			pthread_join(thread[1],(void **)&b2);
			*/
			bootsXOR(&Result[i],b1,carry,EK);
			bootsMUX(carry,b1,carry,&a[i],EK);

		}
	}
	return Result;
}
LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
{

        LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
        LweSample *Result = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

	pthread_t thread[2];
        struct CalcSet *in[2];


	for(int i= bitsize-1; i>minbit ; i--)
	{
		bootsCOPY(&Result[i],&a[i],EK);
	}

        for(int i= minbit ; i >= 0 ; i--)
        {
                if(i == minbit)
                {
                        bootsAND(carry,&a[i],&b[i],EK);
                        bootsXOR(&Result[i],&a[i],&b[i],EK);
                }
                else
                {
			/*
			for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));
*/
                        LweSample *b1;
                        b1 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsXOR(b1,&a[i],&b[i],EK);
/*
			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsCOPY(b2,carry,EK);

                        in[0]->r = &Result[i];
                        in[0]->a = b1;
                        in[0]->b = b2;
                        in[0]->EK= EK;

                        in[1]->r = carry;
                        in[1]->a = b1;
                        in[1]->b = b2;
                        in[1]->c = &a[i];
                        in[1]->EK= EK;

                        pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
                        pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

                        pthread_join(thread[0],(void **)&b1);
                        pthread_join(thread[1],(void **)&b2);
			*/

                        bootsXOR(&Result[i],b1,carry,EK);
                        bootsMUX(carry,b1,carry,&a[i],EK);
                }
        }
        return Result;
}

LweSample* CipherSub(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *O = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
	LweSample *Arv = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

	bootsCONSTANT(O,1,EK);

	/** Reversing bits of b **/

	for(int i = 0; i < bitsize ; i++)
	{
		bootsNOT(&Rev[i],&b[i],EK);
	}

	/** Add one to Reversed bit form of b **/

	for(int i = bitsize-1 ; i >= 0 ; i--)
	{
		if(i == bitsize-1)
		{
			bootsAND(carry,&Rev[i],O,EK);
			bootsXOR(&Arv[i],&Rev[i],O,EK);
		}
		else
		{
			bootsXOR(&Arv[i],&Rev[i],carry,EK);
			bootsAND(carry,carry,&Rev[i],EK);
		}
	}
	
	return CipherAdd(a,Arv,EK);
}

void *thread_adder(void *arg)
{
        struct CipherSet* input = (struct CipherSet*)arg;


        LweSample* Ret = CipherAdd(input->a,input->b,input->EK,input->minbit);

	pthread_exit((void *)Ret);
}

void *thread_initializer(void *arg)
{
	struct MulInitSet* input = (struct MulInitSet*)arg;
	
	input->C = new_gate_bootstrapping_ciphertext_array(bitsize,input->EK->params);
	for(int i=input->ind;i<bitsize;i++)	bootsAND(&input->C[i-input->ind],&input->a[bitsize-1-input->ind],&input->b[i],input->EK);	
	for(int i=bitsize-input->ind;i<bitsize;i++)	bootsCONSTANT(&input->C[i],0,input->EK);
	pthread_exit((void *)input->C);
}
LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
{
	LweSample *Container[bitsize*2];
	pthread_t init[bitsize];

	/** Boost speed by initializing variables concurrently using threads **/

	for(int i = 0 ; i < bitsize ; i++)
	{
		struct MulInitSet *in;
		in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet)); 
		in->C = Container[i];
		in->a = a;
		in->b = b;
		in->EK = EK;
		in->ind = i;
		pthread_create(&init[i],NULL,&thread_initializer,(void*)in);
	}
	for(int i=0;i<bitsize;i++)      pthread_join(init[i],(void **)&Container[i]);
	LweSample *Ret;
	for(int i = 1 ;i < bitsize ; i++)
	{
		if(i == 1)	Ret = CipherAdd(Container[0],Container[1],EK);
		else	Ret = CipherAdd(Ret,Container[i],EK);
	}
	return Ret;
	/** Boost speed by using complete binary-tree based thread calculation **/ 

	/*
	for(int i=0;i<bitsize;i++)	pthread_join(init[i],(void **)&Container[i]);
	
	pthread_t thread[bitsize];

	int len = bitsize/2;
	int pivot = 0;
	while(len>0)
	{	
		for(int i=0;i<len;i++)
		{
			struct CipherSet *in;
			in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
			in->a = Container[pivot+i];
			in->b = Container[pivot+2*len-1-i];
			in->minbit = i+ 1 + pivot/2;
			in->EK = EK;
			pthread_create(&thread[pivot/2+i],NULL,&thread_adder,(void *)in);
		}
		for(int i=0;i<len;i++)	pthread_join(thread[pivot/2+i],(void **)&Container[pivot+len*2+i]);
		pivot+=len*2;
		len/=2;
	}
	
	return Container[2*bitsize-2];
	*/
}


int main(int argc, char *argv[])
{

	if(argc!=5)
	{
		printf("Usage : ./tensor2 <num1> <num2> <mode> <bitsize>\n");
		printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparision\n>");
		exit(0);
	}

	/*if(atoi(argv[4])!=16&&atoi(argv[4])!=32&&atoi(argv[4])!=64)
	{
		printf("Bitsize should be 16 bits or 32 bits or 64 bits.\n");
		exit(0);		
	}*/

	bitsize = atoi(argv[4]);

	// Key_Creation & Encryption Scheme

	const int minimum_lambda = 110;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

	//generate a random key
	uint32_t seed[] = { 314, 1592, 657 };
	tfhe_random_generator_setSeed(seed,3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	testkey = key;
	//export the secret key to file for later use
	FILE* secret_key = fopen("secret.key","wb");
	export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	fclose(secret_key);

	//export the cloud key to a file (for the cloud)
	FILE* cloud_key = fopen("cloud.key","wb");
	export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
	fclose(cloud_key);

	/** Calculation test **/
	int a,b;
	a = atoi(argv[1]);
	b = atoi(argv[2]);
	// CipherText Container 	
	LweSample *t0 = new_gate_bootstrapping_ciphertext_array(bitsize,params);
	LweSample *t1 = new_gate_bootstrapping_ciphertext_array(bitsize,params);
	
	for(int i=0;i<bitsize;i++)
	{
		bootsSymEncrypt(&t0[bitsize-1-i],(a>>i)&0x01,key);
		bootsSymEncrypt(&t1[bitsize-1-i],(b>>i)&0x01,key);
	}
	int mode = atoi(argv[3]);
	printf("\nStart Calculation...\n");
	LweSample* Test;
	if(mode == 1)	Test = CipherAdd(t0,t1,&key->cloud);
	else if(mode == 2) Test = CipherMul(t0,t1,&key->cloud);
	else if(mode == 3) Test = CipherSub(t0,t1,&key->cloud);
	else if(mode == 4) Test = CipherCmp(t0,t1,&key->cloud);
	else	exit(0);
	if(mode < 4)
	{
		int Result = 0;
		for(int i=0;i<bitsize;i++)
		{
			Result<<=1;
			Result+=bootsSymDecrypt(&Test[i],key);
		}	
		printf("Calculation Result : %d\n",Result);
	}
	else
	{
		if(bootsSymDecrypt(Test,key))	printf("It is same value\n");
		else printf("It is not same value\n");
	}
	/** End of Calculation test **/
	
}


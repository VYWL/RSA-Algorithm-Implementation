#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

// functions.h
///////////////////////////////////////////////////

typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;

BOB10_RSA *BOB10_RSA_new();

void printBN(const char *msg, BIGNUM *a);
void PrintUsage();

int BOB10_RSA_free(BOB10_RSA *b10rsa);
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits);
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa);
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa);

// Modular Exponential functions
// usage : r = a ^ e (mod m)
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, const BIGNUM *m);
char * BNtoBinStr(const BIGNUM *n);

// Miller-rabin test
int miller_rabin_test(const BIGNUM *n, int nbits);
int isValid(const BIGNUM *mod, const BIGNUM *a);

// Gen Prime
BIGNUM *GenProbPrime(int pBits);

// XEuclid functions
void BN_one_line_operation (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2, BIGNUM * q, BN_CTX *ctx);
void BN_one_line_copy (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2);
BIGNUM *XEuclid (BIGNUM *x, BIGNUM *y, BIGNUM * input_a, BIGNUM * input_b);


// main.cpp
///////////////////////////////////////////////////

int main (int argc, char *argv[])
{
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();
    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB10_RSA_KeyGen(b10rsa,1024);
        BN_print_fp(stdout,b10rsa->n);
        printf("\n\n");
        BN_print_fp(stdout,b10rsa->e);
        printf("\n\n");
        BN_print_fp(stdout,b10rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b10rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]);
            BOB10_RSA_Enc(out,in, b10rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b10rsa->d, argv[2]);
            BOB10_RSA_Dec(out,in, b10rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);

    return 0;
}



// Implemented Functions (functions.cpp)
///////////////////////////////////////////////////

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

char * BNtoBinStr(const BIGNUM *n) {
    char * nToBinText;

    if (BN_is_zero(n)) {
        nToBinText = (char*) OPENSSL_malloc(2*sizeof(char));
        nToBinText[0] = '0';
        nToBinText[1] = '\0';
        return nToBinText;
    } 
    
    unsigned char *binary = (unsigned char*) OPENSSL_malloc(BN_num_bytes(n)*sizeof(unsigned char));
    
    int len = BN_bn2bin(n, binary);
    nToBinText = (char*) OPENSSL_malloc((len * 8+2)*sizeof(char));

    int offset = 0;
    if (BN_is_negative(n)) {
        nToBinText[0] = '-';
        offset--;
    }

    unsigned char x = binary[0];
    while (!(x & 128) && x) {
        x = x << 1;
        offset++;
    }

    for (int i = 0; i < len; i++) {
        unsigned char bits = binary[i];

        int j=7;
        while(bits) {
        if (bits & 1) {
            nToBinText[8*i+j-offset] = '1';
        } else {
            nToBinText[8*i+j-offset] = '0';
        }
        bits = bits >> 1;
        j--;
        }
        if (i > 0) {
        while (j >= 0) {
            nToBinText[8*i+j-offset] = '0';
            j--;
        }
        }
    }
    nToBinText[8*len-offset] = '\0';
    OPENSSL_free(binary);
    
    return nToBinText;
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, const BIGNUM *m) {

    if(BN_is_zero(e)) {
        BN_dec2bn(&r, "1");
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();


    BIGNUM *c = BN_new();
    BIGNUM *temp_c = BN_new();
    BN_dec2bn(&c, "1");
    BN_mul( c, c, a, ctx);
    BN_mod(c, c, m, ctx);

    char * binaryString = BNtoBinStr(e);
    int len = strlen(binaryString);

    for(int i = 1; i < len; ++i) {
        BN_mod( c, c, m, ctx);

        BN_mul( c, c, c, ctx);

        BN_mod( c, c, m, ctx);
        if((char)binaryString[i] == '1') {
            BN_mul( c, c, a, ctx);
            BN_mod( c, c, m, ctx);
        }
    }

    BN_copy(r, c);

    if(ctx      != NULL) BN_CTX_free(ctx);
    if(c        != NULL) BN_free(c);
    if(temp_c   != NULL) BN_free(temp_c);

    return 1;
}

int miller_rabin_test(const BIGNUM *n, int nbits) {

    if(!BN_is_odd(n)) return 0;

    BN_CTX *ctx = BN_CTX_new();
    int flag = 1;

    BIGNUM *k = BN_new(); 
    BIGNUM *r = BN_new(); 
    BIGNUM *q = BN_new();
    BIGNUM *c = BN_new(); // p - 1 = 2 ^ k * q
    BIGNUM *one = BN_new(); // 1
    BIGNUM *two = BN_new(); // 2
    BIGNUM *a = BN_new(); // 2 ^ k;
    BIGNUM *s = BN_new();
    BN_dec2bn(&one, "1");
    BN_dec2bn(&two, "2");
    BN_dec2bn(&k, "1");
    BN_dec2bn(&a, "1");
    BN_dec2bn(&s, "0");

    // c를 구합니다.
    BN_sub(c, n, one);

    // a 초기값을 2로 정해요.
    BN_mul(a, a, two, ctx);

    // r = c % a;
    BN_mod(r, c, a, ctx);

    while(BN_is_zero(r)) {
        BN_add(k, k, one);

        BN_mul(a, a, two, ctx);
        BN_mod(r, c, a, ctx);
    }
    
    BN_sub(k, k, one); // 하나 더 가서 빼야됨
    ExpMod(a, two, k, n);

    // 나온 k값 가지고 q구하기
    BN_div(q, r, c, a, ctx);

    // random으로 a값 잡되, 1 ~ n-1이어야함.
    BN_sub(c, c, one);
    BN_rand_range(r, c);

    BN_add(r, r, one);
    
    ExpMod(a, r, q, n);

    for(;;) {
        if(!BN_cmp(k, s)) break;

        if(s == 0) {
            if(BN_is_zero(a)) break;
        }
        else {
            if(isValid(n, a)) goto exit;
        }

        BN_mul(q, q, two, ctx);
        BN_add(s, s, one);
        ExpMod(a, r, q, n);

    }

    flag = 0;

exit:
    if(ctx != NULL) BN_CTX_free(ctx);
    if(k != NULL) BN_free(k);
    if(r != NULL) BN_free(r);
    if(q != NULL) BN_free(q);
    if(c != NULL) BN_free(c);
    if(one != NULL) BN_free(one);
    if(two != NULL) BN_free(two);
    if(a != NULL) BN_free(a);
    if(s != NULL) BN_free(s);

    return flag;
}

int isValid(const BIGNUM *mod, const BIGNUM *a) {
    BIGNUM *one = BN_new(); 
    BIGNUM *minus_one = BN_new(); 
    BIGNUM *mod_minus_one = BN_new();
    BIGNUM *res = BN_new();
    BN_dec2bn(&one, "1");
    BN_dec2bn(&minus_one, "-1");
    BN_sub(mod_minus_one, mod, one);

    int is_minus_one = !BN_cmp(a, minus_one);
    int is_mod_minus_one = !BN_cmp(a, mod_minus_one);


    int pass =  is_minus_one | is_mod_minus_one ? 1 : 0;
    return pass;
}


void printBN(const char *msg, BIGNUM *a) {
	char *number_str = BN_bn2dec(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits) {
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *one = BN_new(); BN_dec2bn(&one, "1");
    BIGNUM *zero = BN_new(); BN_dec2bn(&zero, "0");
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    unsigned int pBits = nBits / 2;

    BIGNUM *p = GenProbPrime(pBits);
    BIGNUM *q = GenProbPrime(pBits);


    BN_mul(b10rsa->n, p, q, ctx);

    BN_sub(p, p, one);
    BN_sub(q, q, one);

    BIGNUM *pi = BN_new();
    BN_mul(pi, p, q, ctx);

    BIGNUM *e;
    BIGNUM *d = BN_new();


    for(;;) {

        e = GenProbPrime(50);

        while(!BN_is_one(XEuclid(temp1, temp2, e, pi))) {

            BIGNUM *temp = GenProbPrime(50);
            BN_copy(e, temp);
            BN_free(temp);
        }

        XEuclid(d, temp1, e, pi);

        if(BN_cmp(d, zero) >= 0) break;
        else {
            BN_free(e);
            BN_free(d);
        }

    }

    BN_copy(b10rsa->e, e);
    BN_copy(b10rsa->d, d);

    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(pi != NULL) BN_free(pi);
    if(one != NULL) BN_free(one);
    if(zero != NULL) BN_free(zero);
    if(temp1 != NULL) BN_free(temp1);
    if(temp2 != NULL) BN_free(temp2);
    if(ctx != NULL) BN_CTX_free(ctx);

    return 1;
}

BIGNUM *GenProbPrime(int pBits) {
    BIGNUM *big_Prime = BN_new();

    BN_rand(big_Prime, pBits, 1, 1);

    while (!miller_rabin_test(big_Prime, pBits))
        BN_rand(big_Prime, pBits, 1, 1);
    
    return big_Prime;
}

BOB10_RSA *BOB10_RSA_new() {
    BOB10_RSA *_new = (BOB10_RSA *)(malloc(sizeof(BOB10_RSA)));

    _new->n = BN_new();
    _new->e = BN_new();
    _new->d = BN_new();

    return _new;
}


int BOB10_RSA_free(BOB10_RSA *b10rsa) {
    if(b10rsa->n != NULL) BN_free(b10rsa->n);
    if(b10rsa->e != NULL) BN_free(b10rsa->e);
    if(b10rsa->d != NULL) BN_free(b10rsa->d);

    free(b10rsa);

    return 1;
}

int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa) {
    // c = m ^ e (mod n)
    return ExpMod(c, m, b10rsa->e, (const BIGNUM *)b10rsa->n);
}


int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa) {
    // m = c ^ d (mod n)
    return ExpMod(m, c, b10rsa->d, (const BIGNUM *)b10rsa->n);
}

void BN_one_line_copy (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2) {
    BN_copy(n_1, n_2);
    BN_copy(n_2, n);
}

void BN_one_line_operation (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2, BIGNUM * q, BN_CTX *ctx) {
    BIGNUM *tempMul = BN_new();

    BN_mul(tempMul, n_2, q, ctx);
    BN_sub(n, n_1, tempMul);

	if(tempMul != NULL) BN_free(tempMul);
}

BIGNUM *XEuclid (BIGNUM *x, BIGNUM *y, BIGNUM * input_a, BIGNUM * input_b) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *q = BN_new();
    BIGNUM *r_1 = BN_new();
    BIGNUM *r_2 = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *x_1 = BN_new();
    BIGNUM *x_2 = BN_new();
    BIGNUM *y_1 = BN_new();
    BIGNUM *y_2 = BN_new();
    
    BIGNUM *s = BN_new();
    BIGNUM *t;
    int swapFlag = 0;

    BN_copy(r_1, input_a);
    BN_copy(r_2, input_b);

    if(BN_cmp(r_1, r_2) < 0){
        t = r_1;
        r_1 = r_2;
        r_2 = t;
        swapFlag = 1;
    }

    BN_one(x_1); BN_zero(x_2);
    BN_zero(y_1); BN_one(y_2); 

    if(!BN_div(q, r, r_1, r_2, ctx))
            goto err;

    BN_one_line_operation(r, r_1, r_2, q, ctx);
    BN_one_line_operation(x, x_1, x_2, q, ctx);
    BN_one_line_operation(y, y_1, y_2, q, ctx);

    while(!BN_is_zero(r)) {
        BN_one_line_copy(r, r_1, r_2);
        BN_one_line_copy(x, x_1, x_2);
        BN_one_line_copy(y, y_1, y_2);

        if(!BN_div(q, r, r_1, r_2, ctx))
            goto err;

        BN_one_line_operation(r, r_1, r_2, q, ctx);
        BN_one_line_operation(x, x_1, x_2, q, ctx);
        BN_one_line_operation(y, y_1, y_2, q, ctx);
    }

    if(swapFlag == 1) {
        t = x_2;
        x_2 = y_2;
        y_2 = t;
    }

    BN_copy(x, x_2);
    BN_copy(y, y_2);
    BN_copy(r, r_2);

    if(ctx != NULL) BN_CTX_free(ctx);
    if(r_1 != NULL) BN_free(r_1);
	if(r_2 != NULL) BN_free(r_2);
    if(x_1 != NULL) BN_free(x_1);
	if(y_1 != NULL) BN_free(y_1);
    if(x_2 != NULL) BN_free(x_2);
	if(y_2 != NULL) BN_free(y_2);
	if(s != NULL) BN_free(s);

    return r;

err:
    return NULL;
}
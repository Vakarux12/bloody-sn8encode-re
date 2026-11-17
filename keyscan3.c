// keyscan3 <file> [sig_hex]: find AES-128 key K (contiguous or 16/32-bit strided) with AES_K(fill) XOR sig lane-periodic
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
static unsigned char SIG[16]={0x5c,0xc4,0x1b,0x96,0xfb,0xc8,0x93,0x48,0x94,0xeb,0xe6,0x94,0x85,0x42,0x7a,0x6d};
static EVP_CIPHER_CTX *cx;
static int test(const unsigned char *k, const unsigned char *pt, int dec){
  unsigned char o[32]; int l;
  if(dec) EVP_DecryptInit_ex(cx,EVP_aes_128_ecb(),NULL,k,NULL); else EVP_EncryptInit_ex(cx,EVP_aes_128_ecb(),NULL,k,NULL);
  EVP_CIPHER_CTX_set_padding(cx,0);
  if(dec) EVP_DecryptUpdate(cx,o,&l,pt,16); else EVP_EncryptUpdate(cx,o,&l,pt,16);
  for(int i=0;i<16;i++) o[i]^=SIG[i];
  return !memcmp(o,o+4,4)&&!memcmp(o,o+8,4)&&!memcmp(o,o+12,4);
}
int main(int c,char**v){
  FILE*f=fopen(v[1],"rb"); fseek(f,0,2); long n=ftell(f); rewind(f);
  unsigned char*b=malloc(n); if(fread(b,1,n,f)!=(size_t)n) return 1;
  if(c>2) for(int i=0;i<16;i++) sscanf(v[2]+2*i,"%2hhx",&SIG[i]); // optional sig override for self-test
  cx=EVP_CIPHER_CTX_new();
  unsigned char ff[16],zz[16]; memset(ff,0xff,16); memset(zz,0,16);
  const int strides[3]={1,2,4}; long hits=0;
  for(int si=0;si<3;si++){ int s=strides[si];
    for(long o=0;o+16L*s<=n;o++){ unsigned char k[16];
      for(int i=0;i<16;i++) k[i]=b[o+i*s];
      for(int d=0;d<2;d++){
        if(test(k,ff,d)){printf("HIT stride=%d off=0x%lx fill=FF dec=%d\n",s,o,d);hits++;}
        if(test(k,zz,d)){printf("HIT stride=%d off=0x%lx fill=00 dec=%d\n",s,o,d);hits++;}
      }}}
  fprintf(stderr,"%s: %ld hits\n",v[1],hits); return 0;
}

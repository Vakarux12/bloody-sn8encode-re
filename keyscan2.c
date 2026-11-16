// Scan a binary for an AES-128/256 ECB key that maps the SN8 erased-flash block
// to the firmware signature block, testing Sonix byte-reversed orderings.
// Usage: keyscan2 <datafile>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static const unsigned char CSIG[16] = {
  0x5c,0xc4,0x1b,0x96,0xfb,0xc8,0x93,0x48,0x94,0xeb,0xe6,0x94,0x85,0x42,0x7a,0x6d};

static void rev(unsigned char *d, const unsigned char *s, int n){
  for(int i=0;i<n;i++) d[i]=s[n-1-i];
}
// returns 1 if enc matches C or reverse(C)
static int enc_cmp(const EVP_CIPHER *c, const unsigned char *key,
                   const unsigned char *pt){
  unsigned char out[32]; int outl=0;
  EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx,c,NULL,key,NULL);
  EVP_CIPHER_CTX_set_padding(ctx,0);
  EVP_EncryptUpdate(ctx,out,&outl,pt,16);
  EVP_CIPHER_CTX_free(ctx);
  unsigned char csr[16]; rev(csr,CSIG,16);
  return (memcmp(out,CSIG,16)==0) || (memcmp(out,csr,16)==0);
}

int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"need file\n");return 1;}
  FILE*f=fopen(argv[1],"rb"); if(!f){perror("open");return 1;}
  fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
  unsigned char*buf=malloc(n); fread(buf,1,n,f); fclose(f);

  unsigned char ff[16],zz[16]; memset(ff,0xff,16); memset(zz,0,16);
  unsigned char ffr[16],zzr[16]; rev(ffr,ff,16); rev(zzr,zz,16);
  const unsigned char *pts[4]={ff,zz,ffr,zzr};
  const char *ptn[4]={"FF","00","FFrev","00rev"};
  const EVP_CIPHER *c128=EVP_aes_128_ecb(), *c256=EVP_aes_256_ecb();

  long hits=0;
  for(long o=0;o+16<=n;o++){
    unsigned char kr16[16]; rev(kr16,buf+o,16);
    const unsigned char *k16[2]={buf+o,kr16};
    for(int ki=0;ki<2;ki++) for(int pi=0;pi<4;pi++)
      if(enc_cmp(c128,k16[ki],pts[pi])){
        printf("HIT AES128 off=0x%lx keyrev=%d pt=%s\n",o,ki,ptn[pi]); hits++; }
    if(o+32<=n){
      unsigned char kr32[32]; rev(kr32,buf+o,32);
      const unsigned char *k32[2]={buf+o,kr32};
      for(int ki=0;ki<2;ki++) for(int pi=0;pi<4;pi++)
        if(enc_cmp(c256,k32[ki],pts[pi])){
          printf("HIT AES256 off=0x%lx keyrev=%d pt=%s\n",o,ki,ptn[pi]); hits++; }
    }
    if((o&0xfffff)==0){fprintf(stderr,"\r%ld/%ld",o,n);fflush(stderr);}
  }
  fprintf(stderr,"\ndone, %ld hits\n",hits);
  return 0;
}

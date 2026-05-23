#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <gmp.h>
#include "pbc.h"
#include <math.h>

typedef struct {
    element_t PID1i;
    element_t PID2i;
    element_t ai;
    element_t U;
    element_t xi;
    element_t Xi;
} Vehicle;/*A Vehicle*/

// SHA1
int sha1_160bit_hash(char *hex_hash, const unsigned char *message, size_t msg_len)
{
    if (!hex_hash) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -2;
    unsigned char hash_bin[20];
    unsigned int hash_len;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, message, msg_len);
    EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 20; i++)
        sprintf(hex_hash + i*2, "%02x", hash_bin[i]);
    hex_hash[40] = '\0';
    return 0;
}

int hash_to_zr(element_t z, const unsigned char *data, size_t len) {
    char h[512];
    sha1_160bit_hash(h, data, len);
    element_from_bytes(z, h);
    return 0;
}/*Convert hash value h to an element z in Zr*/

int H1(element_t out, element_t PID1i, element_t PID2i, element_t Xi) {
    char buf[512];
    int pos = 0;
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    pos += element_to_bytes(buf + pos, Xi);
    hash_to_zr(out, buf, pos);
}/*Hash function H1*/

int H2(element_t B, unsigned char *data){
    element_from_hash(B, data, 20);
    return 0;
}

int H3(element_t out, element_t PID1i, element_t PID2i, const char *data){
    char buf[1256];
    int pos=0;
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    hash_to_zr(out, buf, pos);
    return 0;
}

int H4(element_t out, element_t PID1i, element_t PID2i, const char *data){
    char buf[1256];
    int pos=0;
    const char *point="DEFG";
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, point, strlen(point));
    pos += strlen(point);
    hash_to_zr(out, buf, pos);
    return 0;
}

int H5(element_t out, element_t PID1i, element_t PID2i, const char *data){
    char buf[1256];
    int pos=0;
    const char *point="HIGK";
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, point, strlen(point));
    pos += strlen(point);
    hash_to_zr(out, buf, pos);
    return 0;
}

int sha1_binary(const char *msg, unsigned char *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, msg, strlen(msg));
    EVP_DigestFinal_ex(ctx, hash_out, &len);
    EVP_MD_CTX_free(ctx);
    return 0;
}

void Setup(element_t P, element_t Y, element_t Z, element_t y, element_t z) {
    element_mul_zn(Y, P, y);
    element_mul_zn(Z, P, z); 
}

void Keygeneration(element_t xi, element_t Xi, element_t Vi, element_t P){
    element_random(xi);
    element_mul_zn(Xi, P, xi);
}

void Extraction(element_t ai, element_t PID1i, element_t PID2i, element_t Xi, element_t y, element_t z, element_t P, element_t Vi, pairing_t pairing) {
    element_t xi, h1i, h2i, xiZ;
    element_init_Zr(xi, pairing);   
    element_random(xi);
    element_mul_zn(PID1i, P, xi);
    element_init_G1(xiZ, pairing);
    element_mul_zn(xiZ, PID1i, z);
    element_init_G1(h2i, pairing);
    element_from_hash(h2i, xiZ, 20);
    element_add(PID2i, Vi, h2i);
    element_init_Zr(h1i, pairing);
    int ret=H1(h1i, PID1i, PID2i, Xi);
    element_mul(ai, h1i, y);
    element_add(ai, ai, xi);
    element_clear(xi);
    element_clear(xiZ);
    element_clear(h2i);
    element_clear(h1i);
}/*Partial Private Key Extraction*/




int Forge(pairing_t pairing, Vehicle vehicles[40],    element_t S,     const char **m,         element_t P,    element_t Y){
    element_t h10, h30, h40, h50, h3i, h4i, h5i, ri, P1_agg, P2_agg, P3_agg, P4_agg, r0, S1;
    element_t temp_Z1, temp_Z2, temp_Z3, Temp1_G, Temp2_G;
    element_init_Zr(h10, pairing);
    element_init_Zr(h30, pairing);
    element_init_Zr(h40, pairing);
    element_init_Zr(h50, pairing);   
    element_init_Zr(h3i, pairing);
    element_init_Zr(h4i, pairing);
    element_init_Zr(h5i, pairing);    
    element_init_Zr(ri, pairing);
    element_init_Zr(r0, pairing);
    element_init_Zr(S1, pairing);
    element_init_G1(Temp1_G, pairing);
    element_init_G1(Temp2_G, pairing);
    element_init_Zr(P1_agg, pairing);
    element_init_Zr(P2_agg, pairing);
    element_init_Zr(P3_agg, pairing);
    element_init_Zr(P4_agg, pairing);
    element_init_Zr(temp_Z1, pairing);
    element_init_Zr(temp_Z2, pairing);
    element_init_Zr(temp_Z3, pairing);
    element_set0(P1_agg);
    element_set0(P2_agg);
    element_set0(P3_agg);
    element_set0(P4_agg);
    element_neg(Temp1_G,  vehicles[0].Xi);
    for(int i=1; i<40; i++){
       element_random(ri);
       element_mul_zn(Temp2_G, P, ri);
       element_add(vehicles[i].U, Temp1_G, Temp2_G);
       const char *mi = m[i]; 
       H3(h3i, vehicles[i].PID1i, vehicles[i].PID2i, mi);
       H4(h4i, vehicles[i].PID1i, vehicles[i].PID2i, mi);
       H5(h5i, vehicles[i].PID1i, vehicles[i].PID2i, mi);
       element_add(P4_agg, P4_agg, h3i);   
       element_mul(temp_Z1, h3i, ri);
       element_mul(temp_Z2, h4i, vehicles[i].ai);
       element_mul(temp_Z3, h5i, vehicles[i].xi);
       element_add(P1_agg, P1_agg, temp_Z1);
       element_add(P2_agg, P2_agg, temp_Z2);
       element_add(P3_agg, P3_agg, temp_Z3);   
    }
    const char *mi = m[0]; 
    H4(h40, vehicles[0].PID1i, vehicles[0].PID2i, mi);
    H5(h50, vehicles[0].PID1i, vehicles[0].PID2i, mi);
    element_neg(P4_agg, P4_agg);
    element_add(h30, h50, P4_agg);//🔥 Here we force Σh_3i=h_40. It can be realized by TestH.c
    element_random(r0);
    element_mul_zn(vehicles[0].U, P, r0);
    element_add(vehicles[0].U, vehicles[0].U, Temp1_G);
    element_mul(S, h30, r0);
    element_mul(S1, h40, vehicles[0].ai);
    element_add(S, S, S1);      
    element_add(S, S, P1_agg);
    element_add(S, S, P2_agg);
    element_add(S, S, P3_agg);
    element_clear(h10);
    element_clear(h30);
    element_clear(h40);
    element_clear(h50);
    element_clear(h3i);
    element_clear(h4i);
    element_clear(h5i);
    element_clear(ri);
    element_clear(r0);
    element_clear(S1);
    element_clear(Temp1_G);
    element_clear(Temp2_G);
    element_clear(P1_agg);
    element_clear(P2_agg);
    element_clear(P3_agg);
    element_clear(P4_agg);
    element_clear(temp_Z1);
    element_clear(temp_Z2);
    element_clear(temp_Z3);
    return 0;
}/*🔥the adversary does not have vehicle[0].ai or vehicle[0].xi. It cannot modify vehicle V_0's public key or identity/pseudonym*/

int aggregate_verify(pairing_t pairing, Vehicle vehicles[40],      element_t S,     const char **m,            element_t P,    element_t Y) {
    int result = 0;
    element_t  P1_agg, P2_agg, P3_agg, P4_agg, Ti, Xi, temp_G1, temp_G2, temp_G3, temp_G4, temp_G5;
    element_t  h1i, h3i, h4i, h5i, h10, h30, h40, h50, tt;
    element_t e_left, e_right, PID1i, PID2i;
    element_init_Zr(tt, pairing);
    element_init_G1(P1_agg, pairing);
    element_init_G1(P2_agg, pairing);
    element_init_G1(P3_agg, pairing);
    element_init_Zr(P4_agg, pairing);
    element_init_G1(temp_G1, pairing);
    element_init_G1(temp_G2, pairing);
    element_init_G1(temp_G3, pairing);
    element_init_Zr(temp_G4, pairing);
    element_init_G1(temp_G5, pairing);
    element_init_G1(PID1i, pairing);
    element_init_G1(PID2i, pairing);
    element_init_G1(Ti, pairing);
    element_init_G1(Xi, pairing);
    element_init_Zr(h1i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_Zr(h4i, pairing);
    element_init_Zr(h5i, pairing);
    element_init_Zr(h10, pairing);
    element_init_Zr(h30, pairing);
    element_init_Zr(h40, pairing);
    element_init_Zr(h50, pairing);
    element_init_G1(e_left, pairing);
    element_init_G1(e_right, pairing);
    element_set0(P1_agg);
    element_set0(P2_agg);
    element_set0(P3_agg);
    element_set0(P4_agg);
    element_set0(tt);
    // ===================== =====================
    for (int i = 1; i < 40; i++) {
        element_set(PID1i, vehicles[i].PID1i);
        element_set(PID2i, vehicles[i].PID2i);
        element_set(Ti, vehicles[i].U);
        element_set(Xi, vehicles[i].Xi);
        const char *mi = m[i]; 
        H1(h1i, PID1i, PID2i, Xi);        
        H3(h3i, PID1i, PID2i, mi);
        H4(h4i, PID1i, PID2i, mi);
        H5(h5i, PID1i, PID2i, mi);
        element_mul_zn(temp_G1, Ti, h3i);
        element_mul_zn(temp_G2, Xi, h5i);
        element_mul_zn(temp_G3, PID1i, h4i);
        element_mul(temp_G4, h1i, h4i);
        element_add(P1_agg, P1_agg, temp_G1);
        element_add(P2_agg, P2_agg, temp_G2);
        element_add(P3_agg, P3_agg, temp_G3); 
        element_add(P4_agg, P4_agg, temp_G4);
        element_add(tt, tt, h3i);
    }     
    const char *mi = m[0]; 
    H1(h10, vehicles[0].PID1i, vehicles[0].PID2i, vehicles[0].Xi);        
    H4(h40, vehicles[0].PID1i, vehicles[0].PID2i, mi);
    H5(h50, vehicles[0].PID1i, vehicles[0].PID2i, mi);        
    element_neg(tt, tt);
    element_add(h30, tt, h50);
    element_mul_zn(temp_G1, vehicles[0].U, h30);
    element_mul_zn(temp_G2, vehicles[0].PID1i, h40);
    element_mul_zn(temp_G3, vehicles[0].Xi, h50);
    element_mul(temp_G4, h40, h10);
    element_mul_zn(e_left, P, S);   //S*P      
    element_add(e_right, P1_agg, P2_agg);
    element_add(e_right, P3_agg, e_right);
    element_mul_zn(temp_G5, Y, P4_agg);
    element_add(e_right, temp_G5, e_right);
    element_add(e_right, temp_G1, e_right);
    element_add(e_right, temp_G2, e_right);
    element_add(e_right, temp_G3, e_right);
    element_mul_zn(temp_G5, Y, temp_G4);
    element_add(e_right, temp_G5, e_right);    
    element_printf("The e_left is %B\n", e_left);
    element_printf("The e_right is %B\n", e_right);
    result = (element_cmp(e_left, e_right) == 0) ? 1 : 0;
    element_clear(tt);
    element_clear(P1_agg);
    element_clear(P2_agg);
    element_clear(P3_agg);
    element_clear(P4_agg);
    element_clear(temp_G1);
    element_clear(temp_G2);
    element_clear(temp_G3);
    element_clear(temp_G4); 
    element_clear(temp_G5);
    element_clear(h1i);
    element_clear(h3i);
    element_clear(h4i);
    element_clear(h5i);
    element_clear(h10);
    element_clear(h30);
    element_clear(h40);
    element_clear(h50);
    element_clear(Ti);
    element_clear(Xi);
    element_clear(e_left);
    element_clear(e_right);
    element_clear(PID1i);
    element_clear(PID2i);
    return result;
  
}



int main()
{   Vehicle V[40];
    pairing_t pairing;
     pbc_param_t param;
     struct timespec start, end, start1, end1, start2, end2, start3, end3, start4, end4, start5, end5, start6, end6, start7, end7, start8, end8, start12, end12, start_12, end_12;
     double elapsed, elapsed1, elapsed2, elapsed3, elapsed4, elapsed5, elapsed6, elapsed7, elapsed8, elapsed12, elapsed_12;
    pbc_param_init_a_gen(param, 160, 512);
     pairing_init_pbc_param(pairing, param);
   
     const char *msgs[40] = {
    "model 1", "model 2", "model 3", "model 4", "model 5",
    "model 6", "model 7", "model 8", "model 9", "model 10",
    "model 11","model 12","model 13","model 14","model 15",
    "model 16","model 17","model 18","model 19","model 20",
    "model 21", "model 22", "model 23", "model 24", "model 25",
    "model 26", "model 27", "model 28", "model 29", "model 30",
    "model 31","model 32","model 33","model 34","model 35",
    "model 36","model 37","model 38","model 39","model 40"
     };
    
    char hex_hash[41];  
    element_t P, Q, B, Y, Z, y, z, h1i, h2i, h3i,  Vi[40], si[40], left, right, S, h;
    element_init_Zr(h, pairing);
    element_init_Zr(S, pairing);
    element_init_Zr(h1i, pairing);
    element_init_G1(h2i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_G1(left, pairing);
    element_init_G1(right, pairing);
    
     for(int i=0; i<40; i++){
         element_init_G1(Vi[i], pairing);
         element_random(Vi[i]);
         element_init_G1(V[i].PID1i, pairing);
         element_init_G1(V[i].PID2i, pairing);
         element_init_Zr(V[i].ai, pairing); 
         element_init_Zr(si[i], pairing);
         element_init_G1(V[i].U, pairing);
         element_init_G1(V[i].Xi, pairing);
         element_init_Zr(V[i].xi, pairing);
    }

    
         

    
    element_init_Zr(z, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(P, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(Z, pairing);
    element_init_G1(Q, pairing);
    element_random(z);
    element_random(y);
    element_random(P);
    element_random(Q);
    
    clock_gettime(CLOCK_MONOTONIC, &start);

    Setup(P, Y, Z, y, z);
    
    clock_gettime(CLOCK_MONOTONIC, &end); 
    
    
    elapsed = ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9)/20;   
   for(int i=0; i<40; i++){
    Keygeneration(V[i].xi, V[i].Xi, Vi[i], P);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &start1);
    for(int i=0; i<40; i++){
    Extraction(V[i].ai, V[i].PID1i, V[i].PID2i, V[i].Xi, y, z, P, Vi[i], pairing); 
    }
     clock_gettime(CLOCK_MONOTONIC, &end1); 
  elapsed1 = ((end1.tv_sec - start1.tv_sec) + (end1.tv_nsec - start1.tv_nsec) / 1e9)/40;   
       
     clock_gettime(CLOCK_MONOTONIC, &start12);
    for(int i=0; i<40; i++){
      element_mul_zn(left, P, V[i].ai);
      H1(h1i, V[i].PID1i, V[i].PID2i, V[i].Xi);
      element_mul_zn(right, Y, h1i);
      element_add(right, right, V[i].PID1i);
      if (element_cmp(left, right) == 0) {
          printf("%dth Key is generated!\n", i); 
    
          } else {
          printf("%dth Key is not generated!\n", i); 
          }
    }
    clock_gettime(CLOCK_MONOTONIC, &end12); 
    elapsed12 = ((end12.tv_sec - start12.tv_sec) + (end12.tv_nsec - start12.tv_nsec) / 1e9)/40;  
  
     
    Forge(pairing, V, S, msgs,   P, Y);/*🔥all public keys are generated by legitimate vehicles, adversaries cannot modify them*/
  
    int result=aggregate_verify(pairing, V, S, msgs, P, Y);
    if(result)
       printf("The aggregate signature is valid!\n");
    else
       printf("The aggregate signature is not valid");
    element_clear(h);
    element_clear(h1i);
    element_clear(h2i);
    element_clear(h3i);
    //element_clear(B);
   

    for(int i=0; i<40; i++){
       element_clear(V[i].PID1i);
       element_clear(V[i].PID2i);
       element_clear(V[i].ai); 
       element_clear(Vi[i]);
       element_clear(si[i]);
       element_clear(V[i].Xi);
       element_clear(V[i].xi);
}

   
   
    element_clear(z);
    element_clear(y);
    pairing_clear(pairing);
     pbc_param_clear(param);
    return 0;
}



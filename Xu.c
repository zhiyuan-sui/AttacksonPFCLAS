#include "stdio.h"
#include "pbc.h"
#include "gmp.h"
#include "time.h"
#include "openssl/sha.h"
#include "string.h"
#include <stdlib.h> 
#include <openssl/evp.h> 
#include <math.h>



 typedef struct {
    element_t PID1i;
    element_t PID2i;
    element_t ai;
    element_t U;
    element_t xi;
    element_t Xi;
} Vehicle;/*A Vehicle*/
 
int sha1_160bit_hash(char *hex_hash, const unsigned char *message, size_t msg_len)
{
    if (hex_hash == NULL) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -2;
    }

    unsigned char hash_bin[20];  //(160-bit)
    unsigned int hash_len;

    //initialize 
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -3;
    }

    // 2. add data
    EVP_DigestUpdate(ctx, message, msg_len);

    // 3. Compute binary hash
    EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
    EVP_MD_CTX_free(ctx);

    // ==============================================
    // The hash function hex_hash
    // ==============================================
    for (int i = 0; i < 20; i++) {
        sprintf(hex_hash + i*2, "%02x", hash_bin[i]);
    }
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

int H3(element_t out, element_t PID1i, element_t PID2i, element_t B, const char *data, const char *t){
    char buf[1256];
    int pos=0;
    const char *point="ABCD";
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    pos += element_to_bytes(buf + pos, B);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, t, strlen(t));
    pos += strlen(t);
    memcpy(buf+pos, point, strlen(point));
    pos += strlen(point);
    hash_to_zr(out, buf, pos);
    return 0;
}

int H4(element_t out, element_t PID1i, element_t PID2i, element_t B, const char *data, const char *t){
    char buf[1256];
    int pos=0;
    const char *point="DEFG";
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    pos += element_to_bytes(buf + pos, B);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, t, strlen(t));
    pos += strlen(t);
    memcpy(buf+pos, point, strlen(point));
    pos += strlen(point);
    hash_to_zr(out, buf, pos);
    return 0;
}/*Additional hash function H4*/

int H5(element_t out, element_t PID1i, element_t PID2i, element_t B, const char *data, const char *t){
    char buf[1256];
    int pos=0;
    const char *point="HIGK";
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    pos += element_to_bytes(buf+pos, B);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, t, strlen(t));
    pos += strlen(t);
    memcpy(buf+pos, point, strlen(point));
    pos += strlen(point);
    hash_to_zr(out, buf, pos);
    return 0;
}/*Additional hash function H_5*/


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
}/*the setup algorithm*/

void Keygeneration(element_t xi, element_t Xi, element_t Vi, element_t P){
    element_random(xi);
    element_mul_zn(Xi, P, xi);
}/*key generation algorithm*/

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

void sign(element_t si,
          element_t ti,
          element_t PID1i, element_t PID2i,
          element_t ai,
          element_t xi,
          element_t P,
          const char *mi,
          const char *t,
          pairing_t pairing)
{
    element_t h3, h4, h5, temp_zr;
    element_t term_g1, term_g2;
    element_init_Zr(h3, pairing);
    element_init_Zr(h4, pairing);
    element_init_Zr(h5, pairing);
    element_init_Zr(temp_zr, pairing);
    element_init_G1(term_g1, pairing);
    element_init_G1(term_g2, pairing);
  
    element_random(temp_zr);
    element_mul_zn(ti, P, temp_zr);
    H3(h3, PID1i, PID2i, ti, mi, t);
    H4(h4, PID1i, PID2i, ti, mi, t);
    H5(h5, PID1i, PID2i, ti, mi, t); 
    
    element_mul_zn(term_g2, ti, h3);
    element_mul(temp_zr, temp_zr, h3);
    element_mul_zn(term_g1, P, temp_zr);
    element_mul(h4, h4, ai);
    element_mul(h5, h5, xi);     
    element_add(si, h4, temp_zr);
    element_add(si, si, h5);
    element_clear(temp_zr);
    element_clear(h3);
    element_clear(h4);
    element_clear(h5);
    element_clear(term_g1);
    element_clear(term_g2);
}

int verify(pairing_t pairing,
           element_t s_i,
           element_t t_i,
           element_t PID1i, element_t PID2i,
           element_t P,
           element_t Y,
           element_t Xi,
           const char *m_i,
           const char *t)
{
    element_t alpha_i, h3i, h4i, h5i, term_zr;         
    element_t left_term, right_term1, right_term2, right_term3, right_term4;   
    int result = 0;                            
    element_init_Zr(alpha_i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_Zr(h4i, pairing);
    element_init_Zr(h5i, pairing);
    element_init_Zr(term_zr, pairing);
    element_init_G1(left_term, pairing);
    element_init_G1(right_term1, pairing);
    element_init_G1(right_term2, pairing);
    element_init_G1(right_term3, pairing);
    element_init_G1(right_term4, pairing);
    H1(alpha_i, PID1i, PID2i, Xi);        
    H3(h3i, PID1i, PID2i, t_i, m_i, t); 
    H4(h4i, PID1i, PID2i, t_i, m_i, t); 
    H5(h5i, PID1i, PID2i, t_i, m_i, t); 
    element_mul_zn(right_term1, t_i, h3i); 
    element_mul_zn(right_term2, Xi, h5i);
    element_mul_zn(right_term3, PID1i, h4i);
    element_mul(term_zr, h4i, alpha_i);   
    element_mul_zn(right_term4, Y, term_zr);     
    element_add(right_term1, right_term1, right_term2);
    element_add(right_term1, right_term1, right_term3); 
    element_add(right_term1, right_term1, right_term4);
    element_mul_zn(left_term, P, s_i);
    if (element_cmp(left_term, right_term1) == 0) {
        result = 1;
    } else {
        result = 0; 
    }
    element_clear(alpha_i);
    element_clear(h3i);
    element_clear(h4i);
    element_clear(h5i);
    element_clear(term_zr);
    element_clear(left_term);
    element_clear(right_term1);
    element_clear(right_term2);
    element_clear(right_term3);
    element_clear(right_term4);
    return result;
}

int aggregate_verify(pairing_t pairing, Vehicle vehicles[40],      element_t S,     const char **m,        const char *t,            element_t P,    element_t Y) {
    int result = 0;
    element_t  P1_agg, P2_agg, P3_agg, P4_agg, Ti, Xi, temp_G1, temp_G2, temp_G3, temp_G4, temp_Zr;
    element_t  h1i, h3i, h4i, h5i;
    element_t e_left, e_right, PID1i, PID2i;
    element_init_G1(P1_agg, pairing);
    element_init_G1(P2_agg, pairing);
    element_init_G1(P3_agg, pairing);
    element_init_Zr(P4_agg, pairing);
    element_init_G1(temp_G1, pairing);
    element_init_G1(temp_G2, pairing);
    element_init_G1(temp_G3, pairing);
    element_init_G1(temp_G4, pairing);
    element_init_Zr(temp_Zr, pairing);
    element_init_G1(PID1i, pairing);
    element_init_G1(PID2i, pairing);
    element_init_G1(Ti, pairing);
    element_init_G1(Xi, pairing);
    element_init_Zr(h1i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_Zr(h4i, pairing);
    element_init_Zr(h5i, pairing);
    element_init_G1(e_left, pairing);
    element_init_G1(e_right, pairing);
    element_set0(P1_agg);
    element_set0(P2_agg);
    element_set0(P3_agg);
    element_set0(P4_agg);
    // ===================== =====================
    for (int i = 0; i < 40; i++) {
        element_set(PID1i, vehicles[i].PID1i);
        element_set(PID2i, vehicles[i].PID2i);
        element_set(Ti, vehicles[i].U);
        element_set(Xi, vehicles[i].Xi);
        const char *mi = m[i]; 
        H1(h1i, PID1i, PID2i, Xi);        
        H3(h3i, PID1i, PID2i, Ti, mi, t); 
        H4(h4i, PID1i, PID2i, Ti, mi, t);
        H5(h5i, PID1i, PID2i, Ti, mi, t);
        element_mul_zn(temp_G1, Ti, h3i);
        element_mul_zn(temp_G2, Xi, h5i);
        element_mul_zn(temp_G3, PID1i, h4i);
        element_mul(temp_Zr, h1i, h4i);
        element_add(P1_agg, P1_agg, temp_G1);
        element_add(P2_agg, P2_agg, temp_G2);
        element_add(P3_agg, P3_agg, temp_G3); 
        element_add(P4_agg, P4_agg, temp_Zr);
    }     
    element_mul_zn(e_left, P, S);   //S*P      
    element_add(e_right, P1_agg, P2_agg);
    element_add(e_right, P3_agg, e_right);
    element_mul_zn(temp_G4, Y, P4_agg);
    element_add(e_right, temp_G4, e_right);  
    element_printf("The e_left is %B\n", e_left);
    element_printf("The e_right is %B\n", e_right);
    result = (element_cmp(e_left, e_right) == 0) ? 1 : 0;
    element_clear(P1_agg);
    element_clear(P2_agg);
    element_clear(P3_agg);
    element_clear(P4_agg);
    element_clear(temp_G1);
    element_clear(temp_G2);
    element_clear(h1i);
    element_clear(h3i);
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
    const char *t="5th iteration";
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    char hex_hash[41];  
    element_t P, Q, B, Y, Z, y, z, h1i, h2i, h3i,  Vi[40], si[40], left, right;
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
          printf("the %dth Key is generated!\n", i); 
          } else {
          printf("the %dth Key is not generated!\n", i); 
          }
    }
    clock_gettime(CLOCK_MONOTONIC, &end12); 
    elapsed12 = ((end12.tv_sec - start12.tv_sec) + (end12.tv_nsec - start12.tv_nsec) / 1e9)/40;   
     
        clock_gettime(CLOCK_MONOTONIC, &start2);
    for(int i=0; i<40; i++){
       sign(si[i], V[i].U, V[i].PID1i, V[i].PID2i, V[i].ai, V[i].xi, P, msgs[i], t, pairing);
    } 
    clock_gettime(CLOCK_MONOTONIC, &end2); 
    elapsed2 = ((end2.tv_sec - start2.tv_sec) + (end2.tv_nsec - start2.tv_nsec) / 1e9)/40;   
    clock_gettime(CLOCK_MONOTONIC, &start3);      
    for(int i=0; i<40; i++){
        int valid=verify(pairing, si[i], V[i].U, V[i].PID1i, V[i].PID2i, P, Y, V[i].Xi, msgs[i], t);   
        if(valid)
           printf("The %d th individual signature is valid!\n", i);
        else
           printf("The %d th individual signature is not valid", i);
        }
    clock_gettime(CLOCK_MONOTONIC, &end3); 
    elapsed3 = ((end3.tv_sec - start3.tv_sec) + (end3.tv_nsec - start3.tv_nsec) / 1e9)/40;   
          //printf("Execution time of %d verification algorithm: %f seconds\n", i, elapsed3);    
 
    for(int i=1; i<40; i++){
       element_add(si[0], si[0], si[i]);
     }/*Aggregate algorithm*/
   
    int result=aggregate_verify(pairing, V, si[0], msgs,   t, P, Y);
    if(result)
       printf("The aggregate signature is valid!\n");
    else
       printf("The aggregate signature is not valid");
    element_clear(h1i);
    element_clear(h2i);
    element_clear(h3i);
    for(int i=0; i<20; i++){
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



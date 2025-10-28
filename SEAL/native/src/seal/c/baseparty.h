#pragma once
#include "poly.h"

#include "zeroshare.h"
class BaseParty{
public:
    vector<ZeroSharePRNG*> inbox2; 
    vector<ZeroSharePRNG*> outbox;
    bool is_server;
    virtual void echo()=0;
    virtual void make_generator(int t)=0;
    virtual bool registered()=0;
    virtual Poly generate(int64_t req)=0;
    virtual void update_private_share(Poly poly, double_t multiplicand=1, int64_t lagr_lcm=1)=0;
    virtual void private_share_toint()=0;
    virtual Poly& share()=0;
    virtual void generate_poly_A()=0;
    virtual void generate_pki(uint64_t party_id)=0;
    virtual void gather_and_public_pk(vector<double_t> lg, vector<int> id, int64_t mod)=0;
    virtual void partial_decrypt(Ciphertext ctx)=0;
    virtual void gather_and_public_dec(vector<double_t> lagr, vector<int> indices, int64_t lagr_lcm)=0;
    virtual void mask_share(int other_id, double_t weight, int64_t lcm_, Poly& res)=0;
    virtual void update_outbox(vector<int64_t> destination_parties)=0;
    virtual void outbox_push(ZeroSharePRNG* z_ij)=0;
};
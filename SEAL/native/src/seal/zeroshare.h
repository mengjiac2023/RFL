#pragma once
#include "seal/util/rlwe.h"
#include "poly.h"
class ZeroSharePRNG{
private:
    SEALContext context;
    Poly data_;
    uint64_t from_party_id;
    uint64_t to_party_id;
    shared_ptr<UniformRandomGenerator> prng_;
    prng_seed_type seed_;
    string header;

public:
    ZeroSharePRNG(SEALContext ctx, uint64_t from, uint64_t to, prng_seed_type seed):
    context(ctx), from_party_id(from), to_party_id(to), data_(context), seed_(seed){
        header = "from " + to_string(from_party_id) + " to " + to_string(to_party_id) + ".";
        prng_ = UniformRandomGeneratorFactory::DefaultFactory()->create(seed_);
    }
    

    Poly& generate_random_share(){
        data_ = Poly::get_random_poly(context, prng_);
        return data_;
    }
    Poly& data(){
        return data_;
    }
    int64_t get_to_party_id(){
        return to_party_id;
    }
    string debug_string(){
        return header;
    }

    auto &seed(){ return seed_; }
};
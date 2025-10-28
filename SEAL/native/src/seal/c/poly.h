#pragma once
#include <iomanip>
#include "seal/seal.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"

using namespace seal;
using namespace std;
using namespace seal::util;


class Poly: public Plaintext{
public:
    Poly(SEALContext &context,MemoryPoolHandle pool = MemoryManager::GetPool()): 
    Plaintext(pool),
    context_(context){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        coeff_mod_ = parms.coeff_modulus();
        coeff_mod_size_ = coeff_mod_.size();
        poly_coeff_count_ = parms.poly_modulus_degree(); 
        reserve(poly_coeff_count_*coeff_mod_size_);
        resize(poly_coeff_count_*coeff_mod_size_);
        init_double();
        
    }
    Poly(SEALContext &context, const string hex_poly):
    Poly(context){
        operator=(hex_poly);
        init_double();
    }
    Poly(SEALContext &context, Poly& poly):
    Poly(context){
        operator=(poly);
        init_double();
    }
    Plaintext& operator=(const string hex_poly){
        Plaintext::operator=(hex_poly);
        init_double();
        return *this;   
    }
    Plaintext& operator=(Plaintext& ptx){
        return Plaintext::operator=(ptx);
    }

    void add_inplace(Poly other);

    void add_the_multiply_inplace_double(Poly& other, double_t multiplicand);

    inline void init_double(){
        double_data_.resize(coeff_count());
        mod_data_.resize(coeff_count());
        SEAL_ITERATE(seal::util::iter(double_data_.begin(), mod_data_.begin()), coeff_count(), [&](auto I){
            get<0>(I) = 0.0f;//static_cast<double_t>(get<1>(I));
            get<1>(I) = 0;
        });
    }

    inline void to_int(){
        SEAL_ITERATE(seal::util::iter(double_data_.begin(),data()), coeff_count(), [&](auto I){
            get<1>(I) = static_cast<uint64_t>(get<0>(I));
        });
    }

    static Poly get_noise(SEALContext context){
        Poly noise(context);
        auto &context_data = *context.key_context_data();
        auto &zparms = context_data.parms();
        auto ntt_tables = context_data.small_ntt_tables();
        SEAL_NOISE_SAMPLER(zparms.random_generator()->create(), zparms, noise.data());
        // SEAL_ITERATE(iter(noise.data(), size_t(0)), 8, [&](auto I){
        //     get<0>(I) /= 10;
        // });
        
        ntt_negacyclic_harvey(noise.data(), ntt_tables[0]);
        noise.init_double();
        return noise;
    }

    static Poly ones(SEALContext context){
        Poly new_poly(context, "0");
        SEAL_ITERATE(iter(new_poly.data(), new_poly.double_data(), size_t(0)), new_poly.coeff_count(), [&](auto I){
            if(get<2>(I)==0){
                get<0>(I) = 2;
                get<1>(I) = 2.0f;
            }
            else{
            get<0>(I) = 1;
            get<1>(I) = 1.0f;//1.0f;
            }
        });
        return new_poly;
    }
    static Poly get_random_poly(SEALContext context, shared_ptr<UniformRandomGenerator> poly_prng, string what_type="uniform",bool is_ntt=false){
        Poly new_poly(context, "0");
        auto &context_data = *context.key_context_data();
        auto &parms = context_data.parms();
        auto ntt_tables = context_data.small_ntt_tables();
        if(what_type=="uniform"){
            sample_poly_uniform(poly_prng, parms, new_poly.data());
            new_poly.init_double();
            if(is_ntt) inverse_ntt_negacyclic_harvey(new_poly.data(), ntt_tables[0]);
        }
        else{
            Poly temp(context);
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_modulus_size = coeff_modulus.size();
            RNSIter new_poly_iter(temp.data(),coeff_count);
            sample_poly_ternary(poly_prng, parms, new_poly_iter);
            
            if(is_ntt) ntt_negacyclic_harvey(new_poly_iter, coeff_modulus_size, ntt_tables);
            temp.init_double();
            new_poly = temp;
            // new_poly.to_int();
        }
        
        
        return new_poly;
    }

    size_t poly_coeff_count() const{
        return poly_coeff_count_;
    }

    void reserve_double(size_t size){
        
        double_data_.reserve(size);
        reserve(size);
        
    }
    void resize_double(size_t size){
        double_data_.resize(size);
        resize(size);
    }

    void rebalance(int64_t mod=-1){
        if (mod == -1){
            mod = coeff_mod_[0].value();
        }
        SEAL_ITERATE(iter(data(), double_data(), mod_data()), coeff_count(), [&](auto I){
            uint64_t intx = get<0>(I); 
            int64_t  modx = get<2>(I);
            double_t doublex = get<1>(I);
            get<0>(I) = intx % int64_t(mod);
            get<2>(I) += intx / int64_t(mod);
        });
    }

    void make_divisible(int mod){
        SEAL_ITERATE(iter(data(), mod_data()), coeff_count(), [&](auto I){
            uint64_t intx = get<0>(I); 
            int64_t  modx = get<1>(I);
            while(intx % mod != 0){
                intx += coeff_mod_[0].value();
                modx -= 1;
            }
            get<0>(I) = intx;
            get<1>(I) = modx;
        });
    }

    void negate(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        uint64_t mod = coeff_modulus[0].value();
        SEAL_ITERATE(iter(data(),size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) = (mod-get<0>(I))%mod;
        });
    }

    

    string to_string_db();

    inline double_t *double_data(){
        return double_data_.begin();
    }

    inline int64_t *mod_data(){
        return mod_data_.begin();
    }

    inline double_t *get_total(){
        total_data_.resize(coeff_count());
        SEAL_ITERATE(iter(data(),double_data(), mod_data(), total_data_.begin()), coeff_count(), [&](auto I){
            get<3>(I) = get<0>(I) + get<1>(I) + coeff_mod_[0].value()*get<2>(I);
        });
        return total_data_.begin();
    }
    

    PublicKey& to_publickey(Poly a);

    SecretKey& to_secretkey(bool is_initialized=false);

    SecretKey& sk(){
       return sk_; 
    }
    void add_the_multiply_inplace_double2(Poly& other, double_t multiplicand, int64_t mod=-1);
    
    void multiply_polynomial(double_t* other, Poly& result);
    void multiply_polynomial2(Poly other, Poly &result);//, int mod);
private:
    SEALContext context_;
    size_t poly_coeff_count_ = 0;
    DynArray<Modulus> coeff_mod_;
    size_t coeff_mod_size_;
    DynArray<double_t> double_data_;
    DynArray<double_t> total_data_;
    DynArray<int64_t> mod_data_;
    SecretKey sk_;
    bool sk_generated_;
};
#pragma once
#include <iomanip>
#include "seal/seal.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"

// #include "util.h"
using namespace seal;
using namespace std;
using namespace seal::util;


uint64_t modInverse2(uint64_t a, uint64_t m);

int64_t gcd2(int64_t a, uint64_t b);

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
        
        // ntt_negacyclic_harvey(noise.data(), ntt_tables[0]);
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
        // cout << "init: " << to_string() << endl;
        SEAL_ITERATE(iter(data(), mod_data(), size_t(0)), coeff_count(), [&](auto I){
            uint64_t intx = get<0>(I); 
            int64_t  modx = get<1>(I);
            // while(intx % mod != 0){
            //     intx += coeff_mod_[0].value();
            //     modx -= 1;
            // }
            auto coeff_m = coeff_mod_[0].value();
            auto mult_factor = modInverse2(coeff_m, mod)*(mod-intx%mod);
            mult_factor %= mod;
            // if (mult_factor==0 && mod != 1){
            //     cout << " || the zero: " << get<2>(I) << "\t" << intx << "||" << endl;
            // }
            intx += coeff_m*mult_factor;
            modx -= mult_factor;
            
            // cout << mult_factor << "," << mod << "\t";
            get<0>(I) = intx;
            get<1>(I) = modx;
        });
        divide(mod);
        // cout << "after division: "<< to_string() << endl;
    }

    void negate(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        uint64_t mod = coeff_modulus[0].value();
        SEAL_ITERATE(iter(data(),mod_data(),double_data(),size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) = (mod-get<0>(I))%mod;
            get<1>(I) = -get<1>(I);
            get<2>(I) = -get<2>(I);
        });
    }

    void add_the_multiply_inplace(Poly& other,uint64_t mul){
        
        Poly temp(context_, other.to_string());
        uint64_t mod = coeff_mod_[0].value();
        mul %= mod;
        temp.rebalance();
        multiply_poly_scalar_coeffmod(temp.data(),coeff_count(),mul,mod,temp.data());
        add_inplace(temp);
        // SEAL_ITERATE(iter(data(), temp.data()), coeff_count(), [&](auto I){
        //     auto t = multiply_uint_mod(get<1>(I),mul,mod);
            // auto t = get<1>(I) * mul % mod;
            // get<0>(I) = (get<0>(I) + t)%mod;

        // });
    }
    
    void divide(uint64_t div){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        SEAL_ITERATE(iter(data(), mod_data(),size_t(0)), coeff_count(), [&](auto I){
            get<0>(I) /= div;
            // int64_t modx = get<1>(I);
            // int mul = modInverse(div, coeff_modulus[0].value());
            // get<0>(I) += (modx*mul%coeff_modulus[0].value())*coeff_modulus[0].value();
            
        });
        // rebalance();
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
    void ntt_transform(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto ntt_tables = context_data.small_ntt_tables();
        ntt_negacyclic_harvey(data(),ntt_tables[0]);
    }
    void intt_transform(){
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto ntt_tables = context_data.small_ntt_tables();
        inverse_ntt_negacyclic_harvey(data(),ntt_tables[0]);
    }

    void add_the_multiply_inplace_double3(Poly&other, int64_t nom, uint64_t denom){
        Poly other_copy(context_, other.to_string());
        auto reduce = gcd2(nom, denom);
        nom /= reduce;
        denom /= reduce;
        if(nom < 0){
            nom = -nom;
            other_copy.negate();
        }
        other_copy.make_divisible(denom);
        add_the_multiply_inplace(other_copy,nom);//nom);
    }

    void add_the_multiply_inplace_double2(Poly& other, double_t multiplicand, int64_t mod=-1);
    
    void multiply_polynomial(double_t* other, Poly& result);
    void multiply_polynomial2(Poly other, Poly &result);
private:
    SEALContext context_;
    size_t poly_coeff_count_ = 0;
    vector<Modulus> coeff_mod_;
    size_t coeff_mod_size_;
    DynArray<double_t> double_data_;
    DynArray<double_t> total_data_;
    DynArray<int64_t> mod_data_;
    SecretKey sk_;
    bool sk_generated_;
};


#include "poly.h"



void Poly::add_inplace(Poly other){   
    auto dat = data();
    auto other_data = other.data(); 
    auto size = coeff_count();
    auto size_other = other.coeff_count();
    auto max_size = max(size, size_other);
    if(size > size_other){
        auto max_size = size;
        auto min_size = size_other;
        other.reserve(max_size);
        other.resize(max_size);
    }else{
        auto max_size = size_other;
        auto min_size = size;
        reserve(max_size);
        resize(max_size);
    }
    SEAL_ITERATE(iter(data(), other.data(), double_data(), other.double_data(), mod_data(), other.mod_data()),coeff_count(), [&](auto I){
            // int64_t mod = int64_t(coeff_mod_[0].value());
            get<0>(I) += get<1>(I);
            get<2>(I) += get<3>(I);
            get<4>(I) += get<5>(I);
            // double_t res = get<0>(I) + get<1>(I) + get<2>(I) + get<3>(I) + (get<4>(I)+get<5>(I))*mod; 
            // int64_t int_part = int64_t(res);
            // auto temp = int_part % mod;
            // get<4>(I) = int_part / mod;
            // get<2>(I) = res - int_part; 
            // if (temp < 0){
            //     get<4>(I) -= 1;
            //     get<0>(I) = temp + mod;
            // } else get<0>(I) = temp;
        });  
        rebalance();
}

void Poly::add_the_multiply_inplace_double2(Poly& other, double_t multiplicand, int64_t mod){
    auto size = coeff_count();
    auto size_other = other.coeff_count();
    auto max_size = max(size, size_other);

    if(size > size_other){
        auto max_size = size;
        auto min_size = size_other;
        other.reserve_double(max_size);
        other.resize_double(max_size);
    }else{
        auto max_size = size_other;
        auto min_size = size;
        reserve_double(max_size);
        resize_double(max_size);
    } 
    // auto other_double = other.double_data();
    if(mod==-1){
        mod = int64_t(coeff_mod_[0].value());
    }
    SEAL_ITERATE(seal::util::iter(other.data(), data()), coeff_count(), [&](auto I){
        double_t r = multiplicand*get<0>(I);//+get<1>(I);
        int64_t res = static_cast<int64_t>(r)+get<1>(I);
        if(res < 0){
            res = res%mod+mod;
        }
        // cout << int_part << "\t";
        get<1>(I) = static_cast<int64_t>(res);
        
        
    });
}


void Poly::add_the_multiply_inplace_double(Poly& other, double_t multiplicand){
    auto size = coeff_count();
    auto size_other = other.coeff_count();
    auto max_size = max(size, size_other);

    if(size > size_other){
        auto max_size = size;
        auto min_size = size_other;
        other.reserve_double(max_size);
        other.resize_double(max_size);
    }else{
        auto max_size = size_other;
        auto min_size = size;
        reserve_double(max_size);
        resize_double(max_size);
    } 
    auto other_double = other.double_data();
    auto mod = int64_t(coeff_mod_[0].value());

    SEAL_ITERATE(seal::util::iter(other_double, double_data(),other.data(), data(), other.mod_data(), mod_data()), coeff_count(), [&](auto I){
        auto res = multiplicand*(get<0>(I)+get<2>(I)+get<4>(I)*mod) + get<1>(I) + get<3>(I) + get<5>(I)*mod;
        int64_t int_part = static_cast<int64_t>(res);
        
        // cout << int_part << "\t";
        get<1>(I) = res - static_cast<int64_t>(res);
        get<5>(I) = int_part / mod;
        get<3>(I) = int_part%mod;//add_uint_mod(0,int_part,mod);
        
        if (int_part < 0){
            get<5>(I) -= 1;
            get<3>(I) += mod;
        }
    });
}

void Poly::multiply_polynomial(double_t* other_ptr, Poly& result){
    rebalance();
    auto mod = coeff_mod_[0].value();
    SEAL_ITERATE(iter(other_ptr, double_data(), result.double_data(),data(), result.data(),mod_data(), result.mod_data()), coeff_count(), [&](auto I){
        int64_t int_x = get<3>(I), int_z = get<4>(I), mod_x = get<5>(I), mod_z = get<6>(I);
        double_t other = get<0>(I);
        double_t double_x = get<1>(I), double_z = get<2>(I);
        double_t double_y = other - static_cast<int64_t>(other);
        int64_t int_y = static_cast<int64_t>(other) % coeff_mod_[0].value(), mod_y = static_cast<int64_t>(other)/ coeff_mod_[0].value();
        mod_z = mod*mod_x*mod_y + int_x*mod_y+int_y*mod_x;
        int_z = int_x*int_y;
        double_z = mod*(mod_x*double_y+mod_y*double_x)+int_x*double_y+int_y*double_x + double_x*double_y;
        
        int_z += static_cast<int64_t>(double_z);
        
        double_z = double_z - static_cast<int64_t>(double_z);
        mod_z += int64_t(int_z)/int64_t(mod);
        
        int_z = int64_t(int_z) % int64_t(mod);
        if(int_z < 0){
            int_z += mod;
            mod_z -= 1;
        }
        get<4>(I) = int_z;
        get<2>(I) = double_z;
        get<6>(I) = mod_z;
    });
}

void Poly::multiply_polynomial2(Poly other, Poly &result){
    auto mod2 = coeff_mod_[0].value();
    dyadic_product_coeffmod(other.data(), data(), coeff_count(), mod2, result.data());
    // SEAL_ITERATE(iter(other.data(), data(), result.data(), result.mod_data()), coeff_count(), [&](auto I){
    //     get<2>(I) = get<0>(I)*get<1>(I)%mod2;
        
    // });
}

PublicKey& Poly::to_publickey(Poly a){
    PublicKey* pk = new PublicKey();
    auto &context_data = *context_.key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data.small_ntt_tables();
    size_t coeff_modulus_size = coeff_modulus.size();
    
    Ciphertext& destination = pk->data();
    destination.resize(context_, context_data.parms_id(), 2);
    destination.is_ntt_form() = true;
    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    uint64_t *c0 = destination.data();
    uint64_t *c1 = destination.data(1);
    add_poly_coeffmod(c0,data(),coeff_count, coeff_modulus[0],c0);
    add_poly_coeffmod(c1,a.data(),coeff_count, coeff_modulus[0],c1);

    return *pk;
}

SecretKey& Poly::to_secretkey(bool is_initialized)
{
    rebalance();
    auto &context_data = *context_.key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    
    if (!is_initialized)
    {
        // Initialize secret key.
        sk_ = SecretKey();
        sk_generated_ = false;
        sk_.data().resize(mul_safe(coeff_count, coeff_modulus_size));

        // Generate secret key
        SEAL_ITERATE(iter(sk_.data().data(),data()), coeff_count, [&](auto I) {
            get<0>(I) = get<1>(I);
        });
        sk_.parms_id() = context_data.parms_id();
    }

    // Set the secret_key_array to have size 1 (first power of secret)
    // secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
    set_poly(sk_.data().data(), coeff_count, coeff_modulus_size, data());

    // Secret key has been generated
    sk_generated_ = true;
    return sk_;
}

string Poly::to_string_db(){
    std::ostringstream result;
    auto coeff_counts = coeff_count();
    bool empty = true;
    while(coeff_counts--){
        
        if(!empty){
            result << " + (";
        }else result << "(";
        result << double_data_[coeff_counts] << " + " << mod_data_[coeff_counts] << "mod + " << data()[coeff_counts] << ")";
        if(coeff_counts){
            result << "x^" << coeff_counts;
        }
        
        empty = false;
    }
    
    return result.str();
} 



uint64_t modInverse2(uint64_t a, uint64_t m)
{
    uint64_t m0 = m;
    int64_t y = 0, x = 1;
    a %= m;
    if (m == 1)
        return 0;
 
    while (a > 1) {
        // q is quotient
        uint64_t q = a / m;
        uint64_t t = m;
 
        // m is remainder now, process same as
        // Euclid's algo
        m = a % m, a = t;
        t = y;
 
        // Update y and x
        y = x - q * y;
        x = t;
    }
 
    // Make x positive
    if (x < 0)
        x += m0;
 
    return x;
}

int64_t gcd2(int64_t a, uint64_t b){
    if(a < 0){
        a = -a;
    }
    if(b>a){
        return gcd2(b,a);
    }
    if (b == 0)
        return a;
    
    return gcd2(b, a % b);
}
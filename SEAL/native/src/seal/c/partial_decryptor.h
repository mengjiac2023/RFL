#pragma once
#include "seal/decryptor.h"
#include "seal/plaintext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include <vector>
#include <iostream>

class PartialDecryptor : public Decryptor{
public:
    PartialDecryptor(SEALContext& context, const SecretKey &secret_key, Poly ori_sec):sk(ori_sec),Decryptor(context, secret_key){}

    void dot_product_ct_sk_array(Ciphertext &encrypted, Poly& destination, MemoryPoolHandle pool)
    {
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t key_coeff_modulus_size = context_.key_context_data()->parms().coeff_modulus().size();
        size_t encrypted_size = encrypted.size();
        auto is_ntt_form = encrypted.is_ntt_form();

        auto ntt_tables = context_data.small_ntt_tables();

        // Make sure we have enough secret key powers computed
        compute_secret_key_array(encrypted_size - 1);
        
        if (encrypted_size == 2)
        {
            uint64_t* c0 = encrypted.data(0);
            uint64_t* c1 = encrypted.data(1);
            // cout << is_ntt_form << endl;
            if (is_ntt_form)
            {
                set_uint(c1, coeff_count, destination.data());
                dyadic_product_coeffmod(c1, secret_key_array_,coeff_count,coeff_modulus[0],destination.data());
                add_poly_coeffmod(destination.data(), c0, coeff_count, coeff_modulus[0],destination.data());
                
            }
            else
            {
                set_uint(c1, coeff_count, destination.data());
                ntt_negacyclic_harvey_lazy(destination.data(), ntt_tables[0]);
                ntt_negacyclic_harvey_lazy(c0, ntt_tables[0]);
                destination.multiply_polynomial2(sk, destination);
                SEAL_ITERATE(iter(destination.data(), c0),coeff_count, [&](auto I){
                    get<0>(I) += get<1>(I);
                });
                inverse_ntt_negacyclic_harvey_lazy(c0, ntt_tables[0]);
            }
        }
    }
    void bfv_decrypt( Ciphertext &encrypted, Poly &tmp_dest_modq)
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }
       
        dot_product_ct_sk_array(encrypted, tmp_dest_modq, pool_);
        
    }
    void post_process(Poly &destination){
        auto &context_data = *context_.key_context_data();
        auto ntt_tables = context_data.small_ntt_tables();

        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        destination.rebalance();
        inverse_ntt_negacyclic_harvey(destination.data(), ntt_tables[0]);
        RNSIter tmp_dest_modq(destination.data(),coeff_count);
        context_data.rns_tool()->decrypt_scale_and_round(tmp_dest_modq, destination.data(), pool_); 
        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = get_significant_uint64_count_uint(destination.data(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
    }
    private:
        Poly sk;
};
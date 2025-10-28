#pragma once
#include "poly.h"
#include "seal/dynarray.h"
#include <vector>
using namespace std;
using namespace seal;
class MetaPoly{
public:
    using coeff_type = Poly*;
    MetaPoly(SEALContext &context, vector<Poly*> poly_sets):context_(context){
        init(poly_sets);
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        // auto &coeff_modulus = parms.coeff_modulus();
        coeff_mod = parms.coeff_modulus()[0].value();
        
    }
    MetaPoly& operator=(vector<Poly*> sets){
        init(sets);
        return *this;
    }
    Poly operator()(uint64_t input){
        Poly result(context_,"0");
        uint64_t ai = 1;
        // uint64_t coeff_mod = 0xc11;
        SEAL_ITERATE(seal::util::iter(data_.begin(),size_t(0)), coeff_count_, [&](auto I){
            result.add_the_multiply_inplace_double3(*get<0>(I), ai,1);
            ai = (ai*input)%coeff_mod;
            result.rebalance();
        });
        return result;
    }

    void init(vector<Poly*> poly_sets){
        
        data_.reserve(poly_sets.size());
        data_.resize(poly_sets.size());
        int index = 0;
        for(auto poly: poly_sets){
            poly->init_double();
            poly->rebalance();
            data_[index] = poly;
            index += 1;
        }
        
        coeff_count_ = index;
    }

    std::string to_string(){
        std::ostringstream result;
        auto coeff_count = coeff_count_;
        bool empty = true;
        while(coeff_count--){
            
            if(!empty){
                result << " + ";
            }
            result << "(" << data_[coeff_count]->to_string() << ")";
            if(coeff_count){
                result << "y^" << coeff_count;
            }
            empty = false;
        }

        return result.str();
    }
    
    auto data(){
        return data_;
    }
    auto coeff_count(){
        return coeff_count_;
    }
    void add_inplace(MetaPoly &other){
        auto dat = data();
        auto other_data = other.data(); 
        auto size = coeff_count();
        auto size_other = other.coeff_count();
        auto max_size = max(size, size_other);
       
        if(size > size_other){
            auto max_size = size;
            auto min_size = size_other;
        }else{
            auto max_size = size_other;
            auto min_size = size;
        }
        
        for(size_t i = 0; i < max_size; i++){
            dat[i]->add_inplace(*other_data[i]);
        }
    }
private:
    SEALContext context_;
    DynArray<coeff_type> data_;
    size_t coeff_count_;
    uint64_t coeff_mod;
};
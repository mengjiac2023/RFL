#pragma once
#include<vector>

uint64_t modInverse(uint64_t a, uint64_t m)
{
    uint64_t m0 = m;
    int64_t y = 0, x = 1;
 
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

int64_t gcd(int64_t a, int64_t b){
    
    if(b>a){
        return gcd(b,a);
    }
    if (b == 0)
        return a;
    
    return gcd(b, a % b);
}

int64_t lcm(int64_t a, int64_t b){
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    return a*b/gcd(a,b);
}

std::vector<int64_t> lagrange(std::vector<int> indices, int t_threshold, int64_t* lcm_, int mod, int val=0){
     
    std::vector<int64_t> lagrange_(t_threshold);
    std::fill(lagrange_.begin(), lagrange_.end(), 1.0f);
     
    for(size_t i = 0; i < t_threshold; i++){
        int index = indices[i];
        auto lcm_i = 1;
        for(size_t j = 0; j < t_threshold; j++){
            int index_j = indices[j];
            if(index!= index_j){
                lagrange_[i] *= (val-index_j)/gcd(val-index_j,index-index_j);
                lcm_i *= (index-index_j)/gcd(val-index_j,index-index_j);
                auto reduce = gcd(lagrange_[i],lcm_i);
                lagrange_[i] /= reduce;
                lcm_i /= reduce;
            } 
        }      

        if(lcm_i < 0){
            lcm_i = -lcm_i;
            lagrange_[i] = -lagrange_[i];
        }
        
        lcm_[i] = lcm_i;
    } 
    return lagrange_;
}


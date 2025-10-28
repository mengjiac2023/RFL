#pragma once
#include<vector>


uint64_t gcd(int64_t a, int64_t b){
    
    if(b>a){
        return gcd(b,a);
    }
    if (b == 0)
        return a;
    
    return gcd(b, a % b);
}

uint64_t lcm(int64_t a, int64_t b){
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    return a*b/gcd(a,b);
}

std::vector<double_t> lagrange(std::vector<int> indices, int t_threshold, int64_t& lcm_, int val=0){
    // if(val!=0) cout << val << "val" << endl;
    std::vector<double_t> lagrange_(t_threshold);
    std::fill(lagrange_.begin(), lagrange_.end(), 1.0f);
    lcm_ = 1;
    for(size_t i = 0; i < t_threshold; i++){
        int index = indices[i];
        for(size_t j = 0; j < t_threshold; j++){
            int index_j = indices[j];
            if(index!= index_j){
                lagrange_[i] *= static_cast<double_t>(val-index_j)/(float)(index-index_j);
                lcm_ = lcm(lcm_, index-index_j);
            }
        }
    }
    lcm_ *= 2;
    return lagrange_;
}
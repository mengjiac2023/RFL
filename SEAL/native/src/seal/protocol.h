#pragma once
#include "baseparty.h"
#include "seal/seal.h"
#include "util.h"
#include "poly.h"
#include <vector>
#include <unistd.h>
#include <thread>
#include <iostream>
#include <unordered_map>
#include<mutex>
#include <chrono>
std::mutex mtx2;
using namespace std::chrono;
using namespace std;
using namespace seal;
using namespace seal::util;

class Protocol{
    private:
        unordered_map<uint64_t,BaseParty *> parties;
        unordered_map<uint64_t,bool> parties_status;
        map<string,map<uint64_t,vector<string>>> published_message;
        map<pair<uint64_t,uint64_t>,vector<string>> channels;
        uint64_t id_counter;
        uint64_t t_threshold;
        
        Poly secret_poly;
        SEALContext party_context;
    public:
        uint64_t modul;
        uint64_t comm_size;//=0;
        uint64_t server_party_id;
        MetaPoly total_generator;
        Protocol(SEALContext& ctx, uint64_t t):id_counter(0), parties_status({}), t_threshold(t), secret_poly(ctx), party_context(ctx), total_generator(ctx,{}){
            auto &context_data = *ctx.key_context_data();
            auto &parms = context_data.parms();
            modul = parms.coeff_modulus()[0].value();
            comm_size=0;
        }
        inline void calculate_share(uint64_t party_id, string what_protocol="shamir"){
            if(what_protocol=="shamir"){
                calculate_shamir_share(is_first_t_party_online(), party_id);
            }
        }
        
        void clean(){
            published_message["ptxi"].clear();
            published_message["final_dec"].clear();
            // channels.clear();
        }

        void calculate_shamir_share(bool is_first_t_online, uint64_t party_id){
            BaseParty* new_party = parties[party_id];
            
            if(is_first_t_online){
                secret_poly = "0";

                // vector<thread>  pThrds(t_threshold);


                // for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
                // {
                //     pThrds[pIdx] = std::thread([&, pIdx]() {
                //         sleep(100000000);
                //     });
            
                // }
                            
                // for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
                // {
                // //	if(pIdx!=myIdx)
                //     pThrds[pIdx].join();
                // }


 
                    
                for(size_t i = 1; i <= t_threshold; i++){
                
                    BaseParty* generator_party = parties[i];
                    // generator_party->generate(party_id);
                    // mtx2.lock();
                    new_party->update_private_share(generator_party->generate(party_id));
                    // secret_poly.add_inplace(generator_party->generate(0));
                    // cout << "temp seck: " << secret_poly.to_string() << endl;
                    // mtx2.unlock();
                }
                /*vector<int> indices = {};
                for(int i = 0; i < id_counter; i++){
                    if(parties_status[i+1]){
                        indices.push_back(i+1);
                        
                    }
                    if(indices.size()==t_threshold) break;
                } 
                sort(indices.begin(), indices.end());

                //update out_box
                for(size_t i = 0; i < t_threshold; i++){
                    
                    parties[indices[i]]->update_outbox(vector<int64_t>(indices.begin()+i+1, indices.end()));
                }
                //send inbox to outbox
                for(size_t i = 0; i < t_threshold; i++){
                    auto from_p_id = indices[i];
                    for(auto zrshr: parties[from_p_id-1]->outbox){
                        int64_t to_p_id = zrshr->get_to_party_id();
                        
                        auto seed = zrshr->seed();
                        ZeroSharePRNG* x = new ZeroSharePRNG(party_context, from_p_id, to_p_id,seed);
                        parties[to_p_id-1]->inbox2.push_back(x);
                    }
                }*/
            }

            else{
                
                //get online parties indices
                vector<int> indices = {};
                for(int i = 0; i < id_counter; i++){
                    if(parties_status[i+1]){
                        indices.push_back(i+1);
                        
                    }
                    if(indices.size()==t_threshold) break;
                } 
                sort(indices.begin(), indices.end());

                //update out_box
                for(size_t i = 0; i < t_threshold; i++){
                    
                    auto &context_data = *party_context.key_context_data();
                    auto &parms = context_data.parms();
                    auto bootstrap_prng = parms.random_generator()->create();
                    prng_seed_type public_prng_seed;
                    auto destination_parties= vector<int64_t>(indices.begin()+i+1, indices.end());
                    SEAL_ITERATE(iter(&destination_parties[0], size_t(0)), destination_parties.size(), [&](auto I){
                        auto to_party_idx = get<0>(I);
                        auto from_party_idx = party_id;
                        bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));
                        ZeroSharePRNG* z_ij = new ZeroSharePRNG(party_context, from_party_idx, to_party_idx, public_prng_seed);
                        parties[indices[i]]->outbox.push_back(z_ij);
                    });
                }
                //send inbox to outbox
                for(size_t i = 0; i < t_threshold; i++){

                    auto from_p_id = indices[i];
                    // cout << parties[from_p_id]->outbox[0]->debug_string() << endl;
                    for(auto zrshr: parties[from_p_id]->outbox){
                        int64_t to_p_id = zrshr->get_to_party_id();
                        auto seed = zrshr->seed();
                        ZeroSharePRNG* x = new ZeroSharePRNG(party_context, from_p_id, to_p_id,seed);
                        parties[to_p_id]->inbox2.push_back(x);
                    }
                }

                // calculate the share
                int64_t lagr_lcm[t_threshold];// = 1;
                auto lagr = lagrange(indices, t_threshold, lagr_lcm, modul, party_id);

                for(size_t i = 0; i < t_threshold; i++){
                    Poly to_add(party_context); parties[indices[i]]->mask_share(party_id, lagr[i], lagr_lcm[i], to_add);
                    parties[indices[i]]->outbox.clear();
                    parties[indices[i]]->inbox2.clear();
                    
                    new_party->update_private_share(to_add);
                }
            }
        }
        void decrypt(Ciphertext ctx, Plaintext& ptx){
            vector<int> indices = {};
            vector<thread>  pThrds(t_threshold);

            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    indices.push_back(i+1);
                    // parties[i+1]->partial_decrypt(ctx);
                }
                
                if(indices.size()==t_threshold) break;
            } 
            auto start = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>(start-start);
            for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            {
                //uncomment for multithread
                // pThrds[pIdx] = std::thread([&, pIdx]() {
                    start = high_resolution_clock::now();
                    parties[indices[pIdx]]->partial_decrypt(ctx);
                    auto stop = high_resolution_clock::now();
                    duration += duration_cast<microseconds>(stop - start);
                // });

            }
            cout << "average decrypt duration:" << duration.count() / pThrds.size() << "miliseconds" << endl;
            //uncomment for multithread
            // for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            // {
            // //	if(pIdx!=myIdx)
            //     pThrds[pIdx].join();
            // }
            
            int64_t lagr_lcm[t_threshold];// = 1;
            auto lagr = lagrange(indices, t_threshold, lagr_lcm,modul);
            
            // cout << indices[0] << "\t" << indices[1] << endl;
            parties[server_party_id]->gather_and_public_dec(lagr, indices, lagr_lcm);
            auto sz = published_message["final_dec"][server_party_id].size();
            ptx= published_message["final_dec"][server_party_id][sz-1];
        }

        void generate_pk(){
            assign_server();
            parties[server_party_id]->generate_poly_A();
            vector<int> indices = {};
            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    indices.push_back(i+1);
                    parties[i+1]->generate_pki(server_party_id); 
                }
                if(indices.size()==t_threshold) break;
            }
            int64_t the_lcm[t_threshold];// = 1;
            auto lagr = lagrange(indices, t_threshold, the_lcm, modul);
            parties[server_party_id]->gather_and_public_pk(lagr, indices, the_lcm);
        }
        Poly& seckey(){
            secret_poly = "0";
            for(size_t i = 1; i <= t_threshold; ++i){
                BaseParty* generator_party = parties[i];
                secret_poly.add_inplace(generator_party->generate(0));
                if(i>1) total_generator.add_inplace(generator_party->gen());
                else total_generator = generator_party->gen();
            }
            secret_poly.rebalance();
            return secret_poly;
        }

        inline void assign_server(){
            server_party_id = 0;
            for(int i = 0; i < id_counter; i++){
                if(parties_status[i+1]){
                    server_party_id = i+1;
                    parties[i+1]->is_server = true;
                    break;
                }
            }
        }

        inline bool is_first_t_party_online(){
            for(size_t i = 1; i <= t_threshold; i++){
                if(!parties_status[i])
                    return false;
            }
            return true;
        }

        inline uint64_t assign_new_party_id(BaseParty* new_party){
            if(new_party->registered()){return -1;}
            id_counter += 1;
            if(id_counter <= t_threshold){
                new_party->make_generator(t_threshold);
            }
            parties[id_counter]=new_party;
            parties_status[id_counter] = true;
            return id_counter;
        }
        inline void update_online_status(uint64_t party_id, bool connect){
            if(connect){
                parties_status[party_id] = true;
            }else{
                parties_status[party_id] = false;
            }
        }
        inline void update_publised_message(uint64_t party_id,string description, string message){
            published_message[description][party_id].push_back(message);
        }
        inline string public_message(string desc,int published_id, uint64_t msg_id = 0){ 
            if(published_id == -1){published_id = server_party_id;}
            // if(msg_id == 0 && published_message[desc][published_id].size()>0){
            //     msg_id = published_message[desc][published_id].size()-1;
            // }
            return published_message[desc][published_id][msg_id];
        }
        inline void channel_read_request(uint64_t party_id, uint64_t sent_from, vector<string>& inbox){
            auto data = channels[make_pair(sent_from, party_id)];
            for (auto x: data){
                inbox.push_back(x);
            }
        }
        inline void channel_write_request(uint64_t party_id, uint64_t send_to, string message){
            channels[make_pair(party_id, send_to)].push_back(message);
        }
};
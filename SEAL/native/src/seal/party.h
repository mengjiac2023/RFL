#pragma once
#include "protocol.h"
#include "metapoly.h"
// #include "baseparty.h"
#include "seal/seal.h"

#include "seal/util/scalingvariant.h"
#include "partial_decryptor.h"
#include <mutex>
std::mutex mtx;

class Party:public BaseParty{
    SEALContext party_context;
    MetaPoly share_generator;
    Poly private_share;
    
    uint64_t party_id;
    vector<string> inbox;
    bool has_registered, is_pk_fetched, is_decryptor_generated;
    Protocol *proto; // which protocol this party is participating
    PublicKey pk;
    Encryptor* encryptor_ptr;
    PartialDecryptor* decryptor_ptr;
    
public:
    vector<ZeroSharePRNG*> inbox2; //this would be changed to private later when we figure out how to send and receive properly
    vector<ZeroSharePRNG*> outbox;
    bool is_server;
    Party(SEALContext& ctx):party_context(ctx),share_generator(ctx, {}), private_share(ctx), has_registered(false),is_decryptor_generated(false), is_pk_fetched(false), inbox({}),  is_server(false){};
    void register_party(Protocol& protocol){
        
        uint64_t proposed_id = protocol.assign_new_party_id(this);
        
        if(proposed_id != -1){
            party_id = proposed_id; // new party is created
            has_registered = true;
        }   
        proto = &protocol;
        
    }
    void disconnect(){
        proto->update_online_status(party_id, false);
    }
    void connect(){
        proto->update_online_status(party_id, true);
    }

    void broadcast(string desc, Poly message){
        string str;
        str = message.to_string();
        proto->update_publised_message(party_id, desc, str);
    }
    void send(uint64_t to_party_id, string message){
        proto->channel_write_request(party_id, to_party_id, message);
    }
    void receive(uint64_t from_party_id){
        proto->channel_read_request(party_id, from_party_id, inbox);
    }
    string retrieve_from_broadcast(string desc, uint64_t server_id){
        string msg = proto->public_message(desc, server_id);
        return msg;
    }

    void echo(){
        cout << "Hello world i am party " << party_id << endl;
        cout << "My share: " << private_share.to_string() << "\t" << private_share.to_string_db() << endl;
    }
    void make_generator(int t_threshold){
        auto &context_data = *party_context.key_context_data();
        auto &parms = context_data.parms();
        vector<Poly *> list_to_make_metapoly;
         
        for(size_t i = 0; i < t_threshold; i++){
            Poly* new_poly =new Poly(Poly::get_random_poly(party_context, parms.random_generator()->create(), "ternary"));
            list_to_make_metapoly.push_back(new_poly);
            if(i > 0){
                Poly zero_sk = Poly::get_random_poly(party_context,parms.random_generator()->create());
            }
        }
        
        share_generator = list_to_make_metapoly;
        
        
    }
    MetaPoly& gen(){
        return share_generator;
    }
    bool registered(){
        return has_registered;
    }
    Poly generate(int64_t req){
        
        Poly result = share_generator(req);
        return result;
    }
    void update_private_share(Poly poly, double_t multiplicand=1, int64_t lagr_lcm=1){
        if(multiplicand==1){
            private_share.add_inplace(poly);
        }else{
            // poly.make_divisible(lagr_lcm);
            private_share.add_the_multiply_inplace_double3(poly, multiplicand,lagr_lcm);
            poly.rebalance();
        }
    }

    void private_share_toint(){
        private_share.rebalance();
    }
    void update_pk(){
        if(is_pk_fetched) {
            Poly pk_poly(party_context, retrieve_from_broadcast("public_key",-1));
            return;
        }

        Poly pk_poly(party_context, retrieve_from_broadcast("public_key",-1));
        
        Poly a(party_context, retrieve_from_broadcast("poly_A",-1));
        pk_poly.rebalance();
        a.rebalance();
        
        encryptor_ptr = new Encryptor(party_context, pk_poly.to_publickey(a));
        is_pk_fetched = true;
    }

    void encrypt(Plaintext ptx, Ciphertext& ctx){
        update_pk();
        encryptor_ptr->encrypt(ptx, ctx);
    }

    Poly& share(){
        return private_share;
    }
    void generate_poly_A(){
        auto &context_data = *party_context.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        Poly a = Poly::get_random_poly(party_context, UniformRandomGeneratorFactory::DefaultFactory()->create());
        // auto &context_data = *party_context.key_context_data();
        auto ntt_tables = context_data.small_ntt_tables();
        ntt_negacyclic_harvey(a.data(), ntt_tables[0]);
        
        broadcast("poly_A", a);
        proto->comm_size += sizeof(a.to_string());
    }
    void update_outbox(vector<int64_t> destination_parties){
        auto &context_data = *party_context.key_context_data();
        auto &parms = context_data.parms();
        auto bootstrap_prng = parms.random_generator()->create();
        prng_seed_type public_prng_seed;
        SEAL_ITERATE(iter(&destination_parties[0], size_t(0)), destination_parties.size(), [&](auto I){
            auto to_party_idx = get<0>(I);
            auto from_party_idx = party_id;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));
            ZeroSharePRNG* z_ij = new ZeroSharePRNG(party_context, from_party_idx, to_party_idx, public_prng_seed);
            outbox_push(z_ij);
        });
    }
    void outbox_push(ZeroSharePRNG* z_ij){
        outbox.push_back(z_ij);
    }
    void mask_share(int other_id, int64_t weight, int64_t lcm_, Poly& res){
        // private_share.make_divisible(lcm_);
        res.add_the_multiply_inplace_double3(private_share, weight,lcm_);
        private_share.rebalance();
        res.rebalance();
        for(auto zr_shr: inbox2){
            res.add_inplace(zr_shr->generate_random_share());
        }
        for(auto zr_shr: outbox){
            res.add_the_multiply_inplace_double2(zr_shr->generate_random_share(),-1.0);
        }
    }

    void generate_pki(uint64_t server_id){
        Poly *a;
        string msg = retrieve_from_broadcast("poly_A", server_id);
        a = new Poly(party_context, msg);
        Poly public_key(party_context);
        auto &context_data = *party_context.key_context_data();
        auto ntt_tables = context_data.small_ntt_tables();
        ntt_negacyclic_harvey(private_share.data(), ntt_tables[0]);
        a->multiply_polynomial2(private_share, public_key);
        inverse_ntt_negacyclic_harvey(a->data(), ntt_tables[0]);
        inverse_ntt_negacyclic_harvey(private_share.data(), ntt_tables[0]);
        inverse_ntt_negacyclic_harvey(public_key.data(), ntt_tables[0]);
        // cout << a->to_string() << "\t" << private_share.to_string() << "\t" << public_key.to_string() << endl;
        ntt_negacyclic_harvey(a->data(), ntt_tables[0]);
        Poly noise = Poly::get_random_poly(party_context,UniformRandomGeneratorFactory::DefaultFactory()->create(),"ternary");
        public_key.add_inplace(noise);
        public_key.rebalance();
        
        broadcast("pki", public_key);
        proto->comm_size += sizeof(public_key.to_string());
    }
    void gather_and_public_pk(vector<int64_t> lagr, vector<int> indices, int64_t* mod){
        cout << "GATHERING" << endl;
        Poly public_key(party_context);
        vector<thread>  pThrds(indices.size());


        for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
            pThrds[pIdx] = std::thread([&, pIdx]() {
                int id = indices[pIdx];
                int64_t weight = lagr[pIdx];
                Poly pki(party_context,retrieve_from_broadcast("pki", id));
                mtx.lock();
                // cout << weight << "/" << mod[pIdx] << "\t" << id << ":\t" << pki.to_string() << endl;
                
                // pki.make_divisible(mod);
                public_key.add_the_multiply_inplace_double3(pki, weight, mod[pIdx]);
                mtx.unlock();
            });

        }
                    
        for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
        //	if(pIdx!=myIdx)
            pThrds[pIdx].join();
        }

        // for(size_t i = 0; i < indices.size(); i++){
        //     int id = indices[i];
        //     double_t weight = lagr[i];
        //     Poly pki(party_context,retrieve_from_broadcast("pki", id));
        //     // cout << id << ":\t" << pki.to_string() << endl;
        //     // pki.make_divisible(mod);
        //     public_key.add_the_multiply_inplace_double3(pki, weight, mod[i]);
        //     // cout << public_key.to_string() << endl;
            
        // }
        auto &context_data = *party_context.key_context_data();
        auto ntt_tables = context_data.small_ntt_tables();
        ntt_negacyclic_harvey(public_key.data(), ntt_tables[0]);
        public_key.rebalance();
        public_key.negate();
        broadcast("public_key", public_key);
    }
    void partial_decrypt(Ciphertext ctx){
        Poly ptx(party_context);
        auto &context_data = *party_context.key_context_data();
        auto ntt_tables = context_data.small_ntt_tables();
        ntt_negacyclic_harvey(private_share.data(), ntt_tables[0]);
        if(!is_decryptor_generated){
            decryptor_ptr = new PartialDecryptor(party_context, private_share.to_secretkey(), private_share);
            is_decryptor_generated=true;
        }
        inverse_ntt_negacyclic_harvey(private_share.data(), ntt_tables[0]);
        decryptor_ptr->bfv_decrypt(ctx, ptx);
        // ptx.to_int();
        broadcast("ptxi", ptx);
    }
    void gather_and_public_dec(vector<int64_t> lagr, vector<int> indices, int64_t* lagr_lcm){
        Poly ptx(party_context);
        vector<thread>  pThrds(indices.size());
        auto start = high_resolution_clock::now();
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(start-start);
        uint64_t mod = proto->modul;
        for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        {
            // uncomment for multithread
            // pThrds[pIdx] = std::thread([&, pIdx]() {
                int id = indices[pIdx];
                auto weight = lagr[pIdx];
                // mtx.lock();
                Poly ptxi(party_context, retrieve_from_broadcast("ptxi", id));

                // ptxi.make_divisible(lagr_lcm);
                start = high_resolution_clock::now();
                auto factor = modInverse2(lagr_lcm[pIdx],mod)*weight%mod;
                // ptx.add_the_multiply_inplace_double3(ptxi, weight, lagr_lcm[pIdx]);
                // cout << "Changed"<<endl;
                ptx.add_the_multiply_inplace(ptxi,factor);
                stop = high_resolution_clock::now();
                duration += duration_cast<microseconds>(stop - start);
                // mtx.unlock();
            // });

        }
        // uncomment for multithread          
        // for (uint64_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        // {
        // //	if(pIdx!=myIdx)
        //     pThrds[pIdx].join();
        // }
        // for(size_t i = 0; i < indices.size(); i++){
            
        // }
        
        decryptor_ptr->post_process(ptx);
        proto->clean();
        // cout << "final dec:" << ptx.to_string() << endl; 
        broadcast("final_dec", ptx);
        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        cout << "dec reconstruction duration:" << duration.count() << "miliseconds" << endl;
        
    }
};
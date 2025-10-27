import numpy as np
import functools
from tqdm import tqdm
import random
from util import *
from fastecdsa.curve import P256
from fastecdsa.point import Point
from seal import *
class Server:
    servers = []
    server_time = 0
    client_time = 0
    context = None
    G = P256.G
    point0 = G*0
    def __init__(self, id_, context):
        self.id = id_
        self.context = context
        self.t_thr = context.t_threshold
        self.seeds = {}
        if Server.context is None:
            Server.context = context
        if self.id <= context.t_threshold:
            self.secret = np.random.randint(-1,2,(context.degree,1))
            self.secret = np.mod(self.secret, context.coeff_mod).astype(np.int64)
            self.generate = np.random.randint(0,context.coeff_mod, (context.degree,self.t_thr-1),dtype=np.int64)
            self.generate = np.concatenate((self.secret, self.generate),axis=1,dtype=np.int64)
            x = np.load("indices_power.npy").T.astype(np.int64)
            x = x[:context.t_threshold,:]
            self.share_tables = np.mod(np.matmul(self.generate,x),context.coeff_mod)
        Server.servers.append(self)
    
    def generate_share_for(self, other_id):
        return self.share_tables[:,other_id-1]
    
    def get_secret_share(self):
        self.secret_key_share = np.mod(sum([p.generate_share_for(self.id) for p in Server.servers[:self.t_thr]]),self.context.coeff_mod)
        sk = Poly(self.context.seal_context, to_string(self.secret_key_share))
        sk.ntt_transform()
        self.decryptor = ParDec(self.context.seal_context, sk.to_seckey(), sk)
    
    def encrypt_native(self,msgs):
        msgs = msgs.reshape(-1,self.context.degree)
        # print([to_string(msgs[:,i]) for i in range(msgs.shape[1])])
        # ms =msgs[:,0]
        t = time.time()
        res = []
        for i in range(msgs.shape[0]):
            poly = Plaintext(to_string(msgs[i,:]))
            res.append(Server.encryptor.encrypt(poly))
        Server.client_time += (time.time()-t)
        return res

    def __partial_decrypt_native(self,ciphertexts):
        # pass
        # TODO: fill in this code for partial decryptor and collector
        results = [Poly(self.context.seal_context) for _ in range(len(ciphertexts))]
        for ciphertext, result in zip(ciphertexts, results):
            self.decryptor.bfv_decrypt(ciphertext, result)
        return np.array([to_numpy(result.to_string()) for result in results])

    @staticmethod
    def __post_process(result):
        # need to change later so that we don't need decryptor for this
        return Server.servers[0].decryptor.post_process(result)

    
    @staticmethod
    def decrypt_native(ctxs):
        joined_servers = random.sample(Server.servers,Server.context.t_threshold)
        indices = [p.id for p in joined_servers]
        t = time.time()
        messages = [p.__partial_decrypt_native(ctxs) for p in joined_servers] 
        dec_time = (time.time()-t)/len(joined_servers)
        # Server.server_time += dec_time

        lagr = Server.get_lagrange_coeff(indices,0,Server.context.coeff_mod)
        lagr_coeff_time = (time.time()-t)
        # Server.server_time += lagr_coeff_time
        raw, _= Server.__interpolate(messages, lagr, Server.context.coeff_mod) 
        raw = [Poly(Server.context.seal_context,to_string(fin)) for fin in raw]
        [Server.__post_process(fin) for fin in raw]
        return raw

    def encrypt_python(self,ms):
        return encrypt(ms,[Server.pubkey2,Server.pubkeyA],self.context.coeff_mod, self.context.plain_mod) 
    
    def partial_decrypt_python(self,ctx):
        return partial_decrypt(ctx,self.secret_key_share,self.context.coeff_mod, self.context.plain_mod)
    
    @staticmethod
    def decrypt_python(ctxs):
        joined_servers = random.sample(Server.servers,Server.context.t_threshold)
        indices = [p.id for p in joined_servers]
        t = time.time()
        messages = [p.partial_decrypt_python(ctxs) for p in joined_servers] 
        Server.client_time += (time.time()-t)/len(joined_servers)

        t = time.time()
        lagr = Server.get_lagrange_coeff(indices,0,Server.context.coeff_mod)
        Server.server_time += (time.time()-t)

        raw, _= Server.__interpolate(messages, lagr, Server.context.coeff_mod) 
        return np.array([((raw.astype('float')*(Server.context.plain_mod/Server.context.coeff_mod)).round()%Server.context.plain_mod).astype(np.int64)])

    @staticmethod
    def join(party_id):
        joined_servers = random.sample(Server.servers,Server.context.threshold)
        indices = [p.id for p in joined_servers]
        t = time.time()
        lgr_cf = Server.get_lagrange_coeff(indices, party_id, Server.context.coeff_mod)
        Server.server_time += (time.time()-t)



    @staticmethod
    def pubkeygen(threshold):
        joined_servers = random.sample(Server.servers,threshold)
        ctx = joined_servers[0].context
        Server.pubkeyA = np.random.randint(0,ctx.coeff_mod,ctx.degree).astype(np.int64)
        Server.pubkey2 = np.zeros(ctx.degree, dtype=np.int64)
        
        indices = [p.id for p in joined_servers]
        t = time.time()
        lgr_cf = Server.get_lagrange_coeff(indices, 0, ctx.coeff_mod)
        Server.server_time += (time.time()-t)
        t = time.time()
        pkis = [polymul(-Server.pubkeyA,party.secret_key_share, ctx.coeff_mod) for party in joined_servers]
        Server.server_time += (time.time()-t)/len(joined_servers)
        
        Server.pubkey2, Server.partials = Server.__interpolate([pki for pki in pkis], lgr_cf, ctx.coeff_mod)
        t = time.time()
        Server.verify(Server.pubkey2, Server.partials)
        print("PKey Verification time:",time.time()-t)
        Server.pubkey2 = np.mod(Server.pubkey2, Server.context.coeff_mod)
        poly1 = Poly(ctx.seal_context,to_string(Server.pubkey2))
        poly2 = Poly(ctx.seal_context,to_string(Server.pubkeyA))
       
        poly1.ntt_transform()
        poly2.ntt_transform()
        Server.encryptor = Encryptor(ctx.seal_context,poly1.to_pubkey(poly2))

    @staticmethod
    def verify(pubkey2, partials):
        alpha = np.random.randint(0,1024,Server.context.degree).astype(np.int64)#Server.context.coeff_mod
        # partials = np.array(partials)
        # print(partials.shape, alpha.shape)
        # print(sum(partials), pubkey2)
        # Server.G = P256.G
        sum_commited = Server.G*np.matmul(pubkey2,alpha).item()
        commiteds = Server.point0
        # print(commiteds)
        for i in range(len(partials)):
            compressed = np.matmul(partials[i],alpha)
            # print(compressed.shape)
            commited = Server.G*compressed.item()
            commiteds += commited#.append(commited)
        # print(commiteds, sum_commited)
        if commiteds == sum_commited:
            print("PublkeyGen verification passed")
            

    @staticmethod
    def get_lagrange_coeff(list_of_indices, x,coeff_mod):
        """_summary_
            get lagrange coefficient from list of indices and value to be evaluated
        Args:
            list_of_indices: indices of points
            x: value to be evaluated
        Return:
            array of lagrange coefficient: prod(x-xm/xj-xm)
        """
        lx = functools.reduce(lambda x,y:x*y%coeff_mod,[x-m for m in list_of_indices])
        def get_lj(idx,x):
            # return functools.reduce(lambda x,y:x*y%coeff_mod, [(x-m)*pow(idx-m,-1,coeff_mod) for m in list_of_indices if m!=idx])
            # get lj(x) for particular j
            res = lx*pow(x-idx,-1,coeff_mod)%coeff_mod
            denom = functools.reduce(lambda x,y:x*y%coeff_mod,[idx-m for m in list_of_indices if m!=idx],1)
            res = res*pow(denom,-1,coeff_mod)%coeff_mod
            return res
        return np.array([get_lj(j,x) for j in list_of_indices])

    @staticmethod
    def __interpolate(partials,lagrange_coeffs, coeff_mod):    
        res = 0
        import time
        tot = 0
        cli = []
        partials_lagrange = []
        for p,c in zip(partials, lagrange_coeffs):
            tc = time.time()
            tmp = p*c%coeff_mod
            partials_lagrange.append(tmp)
            cli.append(time.time()-tc)
            t = time.time()
            res += tmp
            tot += time.time()-t
        
        Server.server_time += tot
        Server.server_time += sum(cli)/len(cli)
        return res, partials_lagrange #np.mod(res,coeff_mod)

if __name__=="__main__":
    from context import Context
    ctx = Context()
    
    for i in tqdm(range(ctx.n_party)):
        p = Server(i+1, ctx)
    import time
    
    for p in tqdm(Server.servers):
        p.get_secret_share()
    # t = time.time()
    B = pow(2,16)
    t = time.time()
    Server.pubkeygen(ctx.t_threshold)
    print("pubkeygen time:",time.time()-t)
    # print(time.time()-t)
    # print("server:",Server.server_time)
    # print("client:",Server.client_time)
    msg_raw = 2*np.random.rand(ctx.degree*44)-1
    msg = quantize(msg_raw, B)
    from model import SimpleConvNet, LogisticRegression, Classifier
    from torchvision.models import resnet18 
    model =Classifier(input_layer=32*32*3)# #SimpleConvNet(1,10)#Classifier(input_layer=32*32*3)#LogisticRegression(32*32*3,10)#SimpleConvNet(3,10)
    ori = model.state_dict()
    print(Server.servers[0].secret_key_share)
    model2 = SimpleConvNet(1,10)
    ori2 = model2.state_dict()

    info = model_to_flatten_int_vector(ori,2**19)
    msg = info['tensor']
    ori_shape = msg.shape[0]
    print(ori_shape)
    ideal_shape = (int(ori_shape/ctx.degree)+1)*ctx.degree
    padded_msg = np.zeros(ideal_shape)
    padded_msg[:ori_shape] = msg

    info2 = model_to_flatten_int_vector(ori2,2**19)
    msg2 = info2['tensor']
    ori_shape2 = msg2.shape[0]
    ideal_shape2 = (int(ori_shape2/ctx.degree)+1)*ctx.degree
    padded_msg2 = np.zeros(ideal_shape2)
    padded_msg2[:ori_shape] = msg2
    # # print(msg.min())
    # # msg = np.random.randint(20,pow(2,19)-20,ctx.degree*44,dtype=np.int64)
    
    Server.server_time = 0
    Server.client_time = 0
    t = time.time()
    # ctx2 = Server.servers[0].encrypt_native(msg)
    ctx_1s = Server.servers[0].encrypt_native(padded_msg)
    ctx_2s = Server.servers[1].encrypt_native(padded_msg2)
    evaluator = Evaluator(ctx.seal_context)
    ctx_total = [evaluator.add_many([ctx_1,ctx_2]) for ctx_1, ctx_2 in zip(ctx_1s, ctx_2s)]

    print("C++ enc:",time.time()-t)
    t = time.time()
    fins = Server.decrypt_native(ctx_total)
    
    fins = np.concatenate([to_numpy(fin.to_string()) for fin in fins])[:ori_shape]
    print("C++ dec:",time.time()-t)
    info['tensor'] = fins
    recon = flatten_int_vector_to_model(info,2**19)
    for name in ori.keys():
        o = ori[name]
        o2 = ori2[name]
        r = recon[name]
        print((o+o2-r).abs().max())
    # finsq = dequantize(fins, B)
    # z=np.abs(finsq-msg_raw).argmax()
    # print(finsq[z])
    # print(msg_raw[z])
    # print(fins[z],msg[z])
    print("server:",Server.server_time)
    print("client:",Server.client_time)
    
    # t = time.time()
    # for i in range(ctx.n_party):
    #     indices = random.sample(range(1,ctx.n_party), ctx.t_threshold)
    #     lgr =Server.get_lagrange_coeff(indices,0,ctx.coeff_mod)
    #     Server.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    #     Server.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    #     # Server.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    # print(time.time()-t)
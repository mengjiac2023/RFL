import numpy as np
import functools
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from tqdm import tqdm
import random
from util import *
from seal import *
import numpy as np
from fastecdsa.curve import P256
from fastecdsa.point import Point

class Client:
    clients = []
    client_time = 0
    context = None
    G = P256.G
    point0 = G*0
    
    def __init__(self, id_, context):
        self.id = id_
        self.context = context
        self.t_thr = context.t_threshold
        self.seeds = []
        if Client.context is None:
            Client.context = context
        Client.clients.append(self)
    
    def init_as_decryptor(self):
        """初始化为解密者，生成密钥份额相关数据"""
        self.secret = np.random.randint(-1,2,(self.context.degree,1))
        self.secret = np.mod(self.secret, self.context.coeff_mod).astype(np.int64)
        self.generate = np.random.randint(0,self.context.coeff_mod, (self.context.degree,self.t_thr-1),dtype=np.int64)
        self.generate = np.concatenate((self.secret, self.generate),axis=1,dtype=np.int64)
        x = np.load("indices_power.npy").T.astype(np.int64)
        x = x[:self.context.t_threshold,:]
        self.share_tables = np.mod(np.matmul(self.generate,x),self.context.coeff_mod)
    
    def generate_share_for(self, other_id):
        return self.share_tables[:,other_id-1]
    
    def get_secret_share(self):
        # 获取前n_party个解密者的密钥份额
        decryptors = [p for p in Client.clients if p.id <= self.context.n_party]
        self.secret_key_share = np.mod(sum([p.generate_share_for(self.id) for p in decryptors[:self.t_thr]]),self.context.coeff_mod)
        sk = Poly(self.context.seal_context, to_string(self.secret_key_share))
        sk.ntt_transform()
        self.decryptor = ParDec(self.context.seal_context, sk.to_seckey(), sk)
    
    def setup_servers(self, servers):
        for i in range(len(servers)):
            seed = get_random_bytes(16)
            self.seeds.append(seed)
            servers[i].seeds[self.id] = seed

    @staticmethod
    def broadcast_pk(encryptor):
        Client.encryptor = encryptor

    def encrypt_native(self,msgs):
        msgs = msgs.reshape(-1,self.context.degree)
        t = time.time()
        res = []
        for i in range(msgs.shape[0]):
            poly = Plaintext(to_string(msgs[i,:]))
            res.append(Client.encryptor.encrypt(poly))
        Client.client_time += (time.time()-t)
        return res
    
    def encrypt_python(self,ms):
        return encrypt(ms,[Client.pubkey2,Client.pubkeyA],self.context.coeff_mod, self.context.plain_mod) 
    
    def __partial_decrypt_native(self,ciphertexts):
        results = [Poly(self.context.seal_context) for _ in range(len(ciphertexts))]
        for ciphertext, result in zip(ciphertexts, results):
            self.decryptor.bfv_decrypt(ciphertext, result)
        return np.array([to_numpy(result.to_string()) for result in results])

    @staticmethod
    def __post_process(result):
        # 找到第一个解密者
        decryptor = next(p for p in Client.clients if hasattr(p, 'decryptor'))
        return decryptor.decryptor.post_process(result)

    @staticmethod
    def decrypt_native(ctxs):
        # 只从前n_party个客户端中选择解密者
        decryptors = [p for p in Client.clients if p.id <= Client.context.n_party]
        joined_clients = random.sample(decryptors, Client.context.t_threshold)
        indices = [p.id for p in joined_clients]
        t = time.time()
        messages = [p.__partial_decrypt_native(ctxs) for p in joined_clients] 
        dec_time = (time.time()-t)/len(joined_clients)
        # print("Partial decrypt time per client:",dec_time)
        t = time.time()
        lagr = Client.get_lagrange_coeff(indices, 0, Client.context.coeff_mod)
        raw, _= Client.__interpolate(messages, lagr, Client.context.coeff_mod) 
        raw = [Poly(Client.context.seal_context, to_string(fin)) for fin in raw]
        [Client.__post_process(fin) for fin in raw]
        agg_time = time.time() - t
        # print("Aggregation time:",agg_time)
        return raw, dec_time, agg_time

    def partial_decrypt_python(self,ctx):
        return partial_decrypt(ctx,self.secret_key_share,self.context.coeff_mod, self.context.plain_mod)
    
    @staticmethod
    def decrypt_python(ctxs):
        # 只从前n_party个客户端中选择解密者
        decryptors = [p for p in Client.clients if p.id <= Client.context.n_party]
        joined_clients = random.sample(decryptors, Client.context.t_threshold)
        indices = [p.id for p in joined_clients]
        t = time.time()
        messages = [p.partial_decrypt_python(ctxs) for p in joined_clients] 
        Client.client_time += (time.time()-t)/len(joined_clients)

        t = time.time()
        lagr = Client.get_lagrange_coeff(indices, 0, Client.context.coeff_mod)
        Client.client_time += (time.time()-t)

        raw, _= Client.__interpolate(messages, lagr, Client.context.coeff_mod) 
        return np.array([((raw.astype('float')*(Client.context.plain_mod/Client.context.coeff_mod)).round()%Client.context.plain_mod).astype(np.int64)])

    @staticmethod
    def pubkeygen(threshold):
        # 只从前n_party个客户端中选择
        decryptors = [p for p in Client.clients if p.id <= Client.context.n_party]
        joined_clients = random.sample(decryptors, threshold)
        ctx = joined_clients[0].context
        Client.pubkeyA = np.random.randint(0,ctx.coeff_mod,ctx.degree).astype(np.int64)
        Client.pubkey2 = np.zeros(ctx.degree, dtype=np.int64)
        
        indices = [p.id for p in joined_clients]
        t = time.time()
        lgr_cf = Client.get_lagrange_coeff(indices, 0, ctx.coeff_mod)
        Client.client_time += (time.time()-t)
        t = time.time()
        pkis = [polymul(-Client.pubkeyA, party.secret_key_share, ctx.coeff_mod) for party in joined_clients]
        Client.client_time += (time.time()-t)/len(joined_clients)
        
        Client.pubkey2, Client.partials = Client.__interpolate([pki for pki in pkis], lgr_cf, ctx.coeff_mod)
        t = time.time()
        Client.verify(Client.pubkey2, Client.partials)
        print("PKey Verification time:",time.time()-t)
        Client.pubkey2 = np.mod(Client.pubkey2, Client.context.coeff_mod)
        poly1 = Poly(ctx.seal_context, to_string(Client.pubkey2))
        poly2 = Poly(ctx.seal_context, to_string(Client.pubkeyA))
       
        poly1.ntt_transform()
        poly2.ntt_transform()
        Client.encryptor = Encryptor(ctx.seal_context, poly1.to_pubkey(poly2))

    @staticmethod
    def verify(pubkey2, partials):
        alpha = np.random.randint(0,1024,Client.context.degree).astype(np.int64)
        sum_commited = Client.G*np.matmul(pubkey2,alpha).item()
        commiteds = Client.point0
        for i in range(len(partials)):
            compressed = np.matmul(partials[i],alpha)
            commited = Client.G*compressed.item()
            commiteds += commited
        if commiteds == sum_commited:
            print("PublkeyGen verification passed")

    @staticmethod
    def get_lagrange_coeff(list_of_indices, x, coeff_mod):
        lx = functools.reduce(lambda x,y:x*y%coeff_mod,[x-m for m in list_of_indices])
        def get_lj(idx,x):
            res = lx*pow(x-idx,-1,coeff_mod)%coeff_mod
            denom = functools.reduce(lambda x,y:x*y%coeff_mod,[idx-m for m in list_of_indices if m!=idx],1)
            res = res*pow(denom,-1,coeff_mod)%coeff_mod
            return res
        return np.array([get_lj(j,x) for j in list_of_indices])

    @staticmethod
    def __interpolate(partials, lagrange_coeffs, coeff_mod):    
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
        
        Client.client_time += tot
        Client.client_time += sum(cli)/len(cli)
        return res, partials_lagrange

if __name__=="__main__":
    from context import Context
    ctx = Context()
    
    for i in tqdm(range(ctx.n_party)):
        p = Client(i+1, ctx)
        p.init_as_decryptor()
    import time
    
    for p in tqdm(Client.clients):
        p.get_secret_share()
    
    B = pow(2,16)
    t = time.time()
    Client.pubkeygen(ctx.t_threshold)
    print("pubkeygen time:",time.time()-t)
    
    msg_raw = 2*np.random.rand(ctx.degree*44)-1
    msg = quantize(msg_raw, B)
    from model import SimpleConvNet, LogisticRegression, Classifier
    from torchvision.models import resnet18 
    model = Classifier(input_layer=32*32*3)
    ori = model.state_dict()
    print(Client.clients[0].secret_key_share)
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
    
    Client.client_time = 0
    t = time.time()
    ctx_1s = Client.clients[0].encrypt_native(padded_msg)
    ctx_2s = Client.clients[1].encrypt_native(padded_msg2)
    evaluator = Evaluator(ctx.seal_context)
    ctx_total = [evaluator.add_many([ctx_1,ctx_2]) for ctx_1, ctx_2 in zip(ctx_1s, ctx_2s)]

    print("C++ enc:",time.time()-t)
    t = time.time()
    fins = Client.decrypt_native(ctx_total)
    
    fins = np.concatenate([to_numpy(fin.to_string()) for fin in fins])[:ori_shape]
    print("C++ dec:",time.time()-t)
    info['tensor'] = fins
    recon = flatten_int_vector_to_model(info,2**19)
    for name in ori.keys():
        o = ori[name]
        o2 = ori2[name]
        r = recon[name]
        print((o+o2-r).abs().max())
    
    print("client:",Client.client_time)
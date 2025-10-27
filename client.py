import numpy as np
import functools
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from tqdm import tqdm
import random
from util import *
from seal import *
import numpy as np
class Client:
    clients = []
    # server_time = 0
    client_time = 0
    context = None
    def __init__(self, id_, context):
        self.id = id_
        self.context = context
        self.t_thr = context.t_threshold
        self.seeds = []
        Client.clients.append(self)
    
    def setup_servers(self, servers):
        for i in range(len(servers)):
            seed = get_random_bytes(16)
            #self.seeds.append(int.from_bytes(seed,"big"))
            self.seeds.append(seed)
            servers[i].seeds[self.id] = seed

    @staticmethod
    def broadcast_pk(encryptor):
        # self.public_key = pk
        Client.encryptor = encryptor#Encryptor(Client.context.seal_context,pk)
    
    

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
    
    

if __name__=="__main__":
    from context import Context
    ctx = Context()
    
    for i in tqdm(range(ctx.n_party)):
        p = Client(i+1, ctx)
    import time
    
    for p in tqdm(Client.clients):
        p.get_secret_share()
    # t = time.time()
    B = pow(2,16)
    t = time.time()
    Client.pubkeygen(ctx.t_threshold)
    print("pubkeygen time:",time.time()-t)
    # print(time.time()-t)
    # print("server:",Client.server_time)
    # print("client:",Client.client_time)
    msg_raw = 2*np.random.rand(ctx.degree*44)-1
    msg = quantize(msg_raw, B)
    from model import SimpleConvNet, LogisticRegression, Classifier
    from torchvision.models import resnet18 
    model =Classifier(input_layer=32*32*3)# #SimpleConvNet(1,10)#Classifier(input_layer=32*32*3)#LogisticRegression(32*32*3,10)#SimpleConvNet(3,10)
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
    # # print(msg.min())
    # # msg = np.random.randint(20,pow(2,19)-20,ctx.degree*44,dtype=np.int64)
    
    Client.server_time = 0
    Client.client_time = 0
    t = time.time()
    # ctx2 = Client.clients[0].encrypt_native(msg)
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
    # finsq = dequantize(fins, B)
    # z=np.abs(finsq-msg_raw).argmax()
    # print(finsq[z])
    # print(msg_raw[z])
    # print(fins[z],msg[z])
    print("server:",Client.server_time)
    print("client:",Client.client_time)
    
    # t = time.time()
    # for i in range(ctx.n_party):
    #     indices = random.sample(range(1,ctx.n_party), ctx.t_threshold)
    #     lgr =Client.get_lagrange_coeff(indices,0,ctx.coeff_mod)
    #     Client.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    #     Client.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    #     # Client.__interpolate([100 for _ in range(ctx.t_threshold)],lgr,ctx.coeff_mod)
    # print(time.time()-t)

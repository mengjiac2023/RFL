from base64 import encode
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from model import *
from context import Context
import time
from tqdm import tqdm
from server_dual import Server 
from client_dual import Client
from data_util import *
from util import *
from torch import nn
from torch.utils.data import DataLoader
from torch import optim
from torchvision.utils import save_image
from torchvision.models import resnet18
def get_optimizer(model_params):
    # return optim.SGD(model_params,lr=0.1)
    return None
def get_model():
    # model = resnet18()#resnet18() #Classifier(input_layer=28*28)#SimpleConvNet(3,10)#Classifier(input_layer=32*32*3)#SimpleConvNet(1,10)
    # return model#.to('cuda')
    return None
def load_model(state_dict, model):
    # model.load_state_dict(state_dict)
    return None

def get_dataloader(self, batch_size):
    # self.dataset = FedDataset(self.images, self.labels)
    # self.data_loader = DataLoader(self.dataset,shuffle=True,batch_size=batch_size)
    return None
def train(self, local_iter):
    # i = 0
    # while i < local_iter:
    #     for img, lbl in self.data_loader:
    #         i+=1
    #         img = img.to('cuda')
    #         lbl = lbl.to('cuda')
    #         predict = self.model(img)
    #         loss= nn.CrossEntropyLoss()(predict, lbl)
    #         self.optimizer.zero_grad()
    #         loss.backward()
    #         self.optimizer.step()
    #         if i == local_iter:
    #             break
    return None
            
def encode_model(self):
    # self.model_info = model_to_flatten_int_vector(self.model.state_dict(),2**19)
    # msg = self.model_info['tensor']
    # Client.ori_shape = msg.shape[0]
    # ideal_shape = (int(Client.ori_shape/ctx.degree)+1)*ctx.degree
    # self.padded_msg = np.zeros(ideal_shape)
    # self.padded_msg[:Client.ori_shape] = msg
    pass

def decode_model(self, decrypted=None):
    # if decrypted is not None:
    #     self.model_info['tensor'] = decrypted
    # model_state = flatten_int_vector_to_model(self.model_info,2**19)
    # return model_state
    return None
    

def encrypt_model(self):
    ciphertexts = self.encrypt_native(self.padded_msg)
    hash = sha256(b''.join([ciphertext.to_string() for ciphertext in ciphertexts])).hexdigest()
    return ciphertexts, hash

def decrypt_model(ciphertexts,ori_shape=None):
    if ori_shape is None:
        ori_shape = Client.ori_shape
    fins,time1 ,time2 = Client.decrypt_native(ciphertexts)
    fins = np.concatenate([to_numpy(fin.to_string()) for fin in fins])[:ori_shape]
    return fins ,time1, time2

Server.get_dataloader = get_dataloader
Server.train = train
Server.encode_model = encode_model
Server.decode_model = decode_model
Server.encrypt_model = encrypt_model

Client.get_dataloader = get_dataloader
Client.train = train
Client.encode_model = encode_model
Client.decode_model = decode_model
Client.encrypt_model = encrypt_model
Client.decrypt_model = decrypt_model


# def get_data()

ctx = Context()
global_model = get_model()
evaluator= Evaluator(ctx.seal_context)
datasets, labels = share_data_mnist(ctx.n_client)

print("=====================")
print("One-time Client setup")
print("Number of clients (total): {}".format(ctx.n_client))
print("Number of decryptors: {}".format(ctx.n_party))
print("Threshold:         {}".format(ctx.t_threshold))
print("=====================")
print("Initializing clients")
for i in tqdm(range(ctx.n_client),ncols=50):
    p = Client(i+1, ctx)
    # 前n_party个客户端初始化为解密者
    if i < ctx.n_party:
        p.init_as_decryptor()
    # p.model = get_model()
    # p.optimizer = get_optimizer(p.model.parameters())
    # load_model(global_model.state_dict(), p.model)
    p.images = datasets[i]
    p.labels = labels[i]
    p.get_dataloader(ctx.local_batch_size)
    
print("SkeyGen starts (for first {} clients)".format(ctx.n_party))
for p in tqdm(Client.clients[:ctx.n_party],ncols=50):
    p.get_secret_share()
print("SkeyGen finishes")
print("PkeyComp starts")
Client.pubkeygen(ctx.t_threshold)
print("PKeyComp finishes")
print("====One-time Setup Finish====")

print("=====================")
print("Creating 2 servers for aggregation")
for i in range(2):
    s = Server(i+1, ctx)
    # 设置服务器的seeds（如果需要的话）
    for p in Client.clients:
        if hasattr(p, 'seeds'):
            seed = get_random_bytes(16)
            s.seeds[p.id] = seed
print("Servers created")
print("=====================")

def secure_aggregation(party_indices):
    avg_time = 0
    t = time.time()
    all_ciphertexts = []
    for party_id in tqdm(party_indices,ncols=50):
        p = Client.clients[party_id]
        t0 = time.time()
        p.encode_model()
        all_ciphertexts.append(p.encrypt_model()[0])
        Client.client_time += (time.time()-t0)
    avg_time += (time.time()-t)/len(party_indices)
    print(avg_time)
    t= time.time()
    ctx_total = [evaluator.add_many([ciphertext[i] for ciphertext in all_ciphertexts]) for i in range(len(all_ciphertexts[0]))]
    hash = sha256(b''.join([ciphertext.to_string() for ciphertext in ctx_total])).hexdigest()
    Server.server_time += time.time()-t
    avg_time += time.time()-t
    print(avg_time)
    t= time.time()
    final_dec = Client.decrypt_model(ctx_total)
    avg_time += (time.time()-t)/Client.context.t_threshold
    print(avg_time)
    t = time.time()
    final_dec = p.decode_model(final_dec)
    load_model(final_dec,global_model)
    avg_time += time.time()-t
    return avg_time

def secure_aggregation_vector(party_indices, vector_length):
    Server.server_time = 0
    avg_time = 0
    t = time.time()
    all_ciphertexts = []
    for party_id in tqdm(party_indices,ncols=50):
        t0 = time.time()
        p = Client.clients[party_id]
        # p.encode_model()
        ideal_shape = (int(vector_length/ctx.degree)+1)*ctx.degree
        p.padded_msg = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.uint32)
        all_ciphertexts.append(p.encrypt_model()[0])
        # Client.client_time += (time.time()-t0)
    avg_time += (time.time()-t)/len(party_indices)
    print("Client encrypt time: {:.4f} seconds".format(avg_time))
    t= time.time()
    ctx_total = [evaluator.add_many([ciphertext[i] for ciphertext in all_ciphertexts]) for i in range(len(all_ciphertexts[0]))]
    hash = sha256(b''.join([ciphertext.to_string() for ciphertext in ctx_total])).hexdigest()
    Server.server_time += time.time()-t
    new_time = time.time()-t
    avg_time += new_time
    print("Server eval(add) time: {:.4f} seconds".format(new_time))
    t= time.time()
    final_dec = Client.decrypt_model(ctx_total, ctx.vector_length)
    new_time = (time.time()-t)
    Server.server_time += new_time
    avg_time += new_time
    print("Client decrypt time: {:.4f} seconds".format(new_time))
    t = time.time()
    # final_dec = p.decode_model(final_dec)
    # load_model(final_dec,global_model)
    avg_time += time.time()-t
    return avg_time

def secure_aggregation_vector_two(party_indices, vector_length):
    Server.server_time = 0
    avg_time = 0
    
    # 通信开销统计（字节）
    client_upload_size = 0  # 客户端上传密文的大小
    server_to_decryptor_size = 0  # 服务器发送给解密者的大小
    decryptor_to_server_size = 0  # 解密者发送结果的大小
    server_broadcast_size = 0  # 服务器广播结果的大小
    
    # 将客户端分成两组
    half_clients = len(party_indices) // 2
    group1_indices = party_indices[:half_clients]
    group2_indices = party_indices[half_clients:]
    
    ideal_shape = (int(vector_length/ctx.degree)+1)*ctx.degree
    
    t = time.time()
    all_ciphertexts_1 = []
    all_ciphertexts_2 = []
    
    # 第一组客户端加密
    for party_id in tqdm(group1_indices, desc="Group1 encrypt", ncols=50):
        p = Client.clients[party_id]
        p.padded_msg = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.uint32)
        ctx_m = p.encrypt_model()[0]
        all_ciphertexts_1.append(ctx_m)
        # 计算上传大小
        ctx_size = sum([len(c.to_string()) for c in ctx_m])
        client_upload_size += ctx_size
    
    # 第二组客户端加密
    for party_id in tqdm(group2_indices, desc="Group2 encrypt", ncols=50):
        p = Client.clients[party_id]
        p.padded_msg = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.uint32)
        ctx_m = p.encrypt_model()[0]
        all_ciphertexts_2.append(ctx_m)
        # 计算上传大小
        ctx_size = sum([len(c.to_string()) for c in ctx_m])
        client_upload_size += ctx_size
    
    avg_client_upload = client_upload_size / len(party_indices)
    enc_time = (time.time()-t)/len(party_indices)
    avg_time += enc_time
    print("Client encrypt time: {:.4f} seconds".format(avg_time))
    
    # 服务器聚合第一组
    t= time.time()
    ctx_total_1 = [evaluator.add_many([ciphertext[i] for ciphertext in all_ciphertexts_1]) for i in range(len(all_ciphertexts_1[0]))]
    
    # 服务器聚合第二组
    ctx_total_2 = [evaluator.add_many([ciphertext[i] for ciphertext in all_ciphertexts_2]) for i in range(len(all_ciphertexts_2[0]))]
    
    Server.server_time += time.time()-t
    add_time = time.time()-t
    avg_time += add_time
    print("Server eval(add) time: {:.4f} seconds".format(add_time))

    # 计算单个服务器发送给所有解密者的大小（发送聚合后的密文）
    server_to_decryptor_size = sum([len(c.to_string()) for c in ctx_total_1])*ctx.n_party
    # server_to_decryptor_size = sum(len(c.to_string()) for c in ctx_total_1) * ctx.n_party
    
    # 解密第一组
    t= time.time()
    final_dec_1, dec_time_1, agg_time_1 = Client.decrypt_model(ctx_total_1, vector_length)
    
    # 解密第二组
    final_dec_2, dec_time_2, agg_time_2 = Client.decrypt_model(ctx_total_2, vector_length)

    new_time = dec_time_1 + dec_time_2 + agg_time_1
    Server.server_time += new_time
    avg_time += new_time
    print("Client decrypt time: {:.4f} seconds".format(dec_time_1+dec_time_2))
    print("Server agg time: {:.4f} seconds".format(agg_time_1))
    # 计算单个解密者发送结果的大小（发送两部分明文结果）
    decryptor_to_server_size = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.uint32).nbytes * 2
    
    # 计算单个服务器广播结果的大小（广播给所有客户端）
    server_broadcast_size = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.uint32).nbytes * len(party_indices)
    
    print("=" * 50)
    print("Communication Overhead Summary:")
    print("  Client upload (avg):          {:.2f} MB".format(avg_client_upload / (1024*1024)))
    print("  Server to decryptors:         {:.2f} MB".format(server_to_decryptor_size / (1024*1024)))
    print("  Decryptors to server:         {:.2f} MB".format(decryptor_to_server_size / (1024*1024)))
    print("  Server broadcast (total):     {:.2f} MB".format(server_broadcast_size / (1024*1024)))
    print("=" * 50)

    print("=" * 50)
    print("Com Overhead Summary:")
    print("  Client:          {:.4f} seconds".format(enc_time))
    print("  Decryptors:         {:.4f} seconds".format(enc_time+dec_time_1+dec_time_2))
    print("  Server:     {:.4f} seconds".format(agg_time_1+add_time))
    print("Communication Overhead Summary:")
    print("  Client:          {:.2f} MB".format(avg_client_upload / (1024*1024)))
    print("  Decryptors:         {:.2f} MB".format((decryptor_to_server_size+avg_client_upload) / (1024*1024)))
    print("  Server:     {:.2f} MB".format((server_broadcast_size+server_to_decryptor_size) / (1024*1024)))
    print("=" * 50)
    
    t = time.time()
    avg_time += time.time()-t
    return avg_time

Client.broadcast_pk(Client.encryptor)
ppr = ctx.n_client
import random

def total_train(num_round):
    train_times=[]
    secagg_times=[]
    for i in range(num_round):
        joined = random.sample(range(ctx.n_client),ppr)
        t = time.time()
        print("{} clients start training for round {}".format(ppr,i+1))
        for p_id in joined:#tqdm(joined):
            party = Client.clients[p_id]
            party.train(0)
        train_time = (time.time()-t)/ppr
        # t = time.time()
        
        secagg_time = secure_aggregation_vector_two(joined,ctx.vector_length)
        train_times.append(train_time)
        secagg_times.append(secagg_time)
    print("SA time: {:.4f}".format(sum(secagg_times)/num_round))
    print("FL+SA time: {:.4f}".format(sum(secagg_times)/num_round + sum(train_times)/num_round))

total_train(1)
print("Server time: {}".format(Server.server_time))
print("Client time: {}".format(Client.client_time/ctx.n_client))
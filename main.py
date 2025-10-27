from base64 import encode
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from model import *
from context import Context
import time
from tqdm import tqdm
from server import Server 
from client import Client
from data_util import *
from util import *
from torch import nn
from torch.utils.data import DataLoader
from torch import optim
from torchvision.utils import save_image
from torchvision.models import resnet18
def get_optimizer(model_params):
    return optim.SGD(model_params,lr=0.1)
def get_model():
    model = resnet18()#resnet18() #Classifier(input_layer=28*28)#SimpleConvNet(3,10)#Classifier(input_layer=32*32*3)#SimpleConvNet(1,10)
    return model#.to('cuda')

def load_model(state_dict, model):
    model.load_state_dict(state_dict)

def get_dataloader(self, batch_size):
    self.dataset = FedDataset(self.images, self.labels)
    self.data_loader = DataLoader(self.dataset,shuffle=True,batch_size=batch_size)

def train(self, local_iter):
    i = 0
    while i < local_iter:
        for img, lbl in self.data_loader:
            i+=1
            img = img.to('cuda')
            lbl = lbl.to('cuda')
            predict = self.model(img)
            loss= nn.CrossEntropyLoss()(predict, lbl)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            if i == local_iter:
                break
            
def encode_model(self):
    self.model_info = model_to_flatten_int_vector(self.model.state_dict(),2**19)
    msg = self.model_info['tensor']
    Server.ori_shape = msg.shape[0]
    ideal_shape = (int(Server.ori_shape/ctx.degree)+1)*ctx.degree
    self.padded_msg = np.zeros(ideal_shape)
    self.padded_msg[:Server.ori_shape] = msg

def decode_model(self, decrypted=None):
    if decrypted is not None:
        self.model_info['tensor'] = decrypted
    model_state = flatten_int_vector_to_model(self.model_info,2**19)
    return model_state
    

def encrypt_model(self):
    ciphertexts = self.encrypt_native(self.padded_msg)
    hash = sha256(b''.join([ciphertext.to_string() for ciphertext in ciphertexts])).hexdigest()
    return ciphertexts, hash

def decrypt_model(ciphertexts,ori_shape=None):
    if ori_shape is None:
        ori_shape = Server.ori_shape
    fins = Server.decrypt_native(ciphertexts)
    fins = np.concatenate([to_numpy(fin.to_string()) for fin in fins])[:ori_shape]
    return fins

Server.get_dataloader = get_dataloader
Server.train = train
Server.encode_model = encode_model
Server.decode_model = decode_model
Server.encrypt_model = encrypt_model
Server.decrypt_model = decrypt_model

Client.get_dataloader = get_dataloader
Client.train = train
Client.encode_model = encode_model
Client.decode_model = decode_model
Client.encrypt_model = encrypt_model


# def get_data():

ctx = Context()
global_model = get_model()
evaluator= Evaluator(ctx.seal_context)
datasets, labels = share_data_mnist(ctx.n_client)

print("=====================")
print("One-time Server setup")
print("Number of servers: {}".format(ctx.n_party))
print("Threshold:         {}".format(ctx.t_threshold))
print("=====================")
print("Initializing servers")
for i in tqdm(range(ctx.n_party),ncols=50):
    p = Server(i+1, ctx)
    
print("SkeyGen starts")
for p in tqdm(Server.servers,ncols=50):
    p.get_secret_share()
print("SkeyGen finishes")
print("PkeyComp starts")
Server.pubkeygen(ctx.t_threshold)
print("PKeyComp finishes")
print("====One-time Setup Finish====")
print("=============================")
print("Initializing clients")
print("Number of clients: {}".format(ctx.n_client))
print("Neural network size: {}".format(ctx.vector_length))#count_parameters(global_model)))
print("=============================")
for i in tqdm(range(ctx.n_client),ncols=50):
    p = Client(i+1, ctx)
    p.setup_servers(Server.servers)
    p.model = get_model()
    p.optimizer = get_optimizer(p.model.parameters())
    load_model(global_model.state_dict(), p.model)
    p.images = datasets[i]
    p.labels = labels[i]
    p.get_dataloader(ctx.local_batch_size)

def secure_aggregation(party_indices):
    avg_time = 0
    t = time.time()
    all_ciphertexts = []
    for party_id in tqdm(party_indices,ncols=50):
        p = Client.clients[party_id]
        t0 = time.time()
        p.encode_model()
        all_ciphertexts.append(p.encrypt_model()[0])
        Client.client_time += (time.time()-t0)#/len(party_indices)
    avg_time += (time.time()-t)/len(party_indices)
    print(avg_time)
    t= time.time()
    ctx_total = [evaluator.add_many([ciphertext[i] for ciphertext in all_ciphertexts]) for i in range(len(all_ciphertexts[0]))]
    hash = sha256(b''.join([ciphertext.to_string() for ciphertext in ctx_total])).hexdigest()
    Server.server_time += time.time()-t
    avg_time += time.time()-t
    print(avg_time)
    t= time.time()
    final_dec = Server.decrypt_model(ctx_total)
    avg_time += (time.time()-t)/Server.context.t_threshold
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
        p.padded_msg = (np.random.rand(ideal_shape)*ctx.plain_mod).astype(np.int64)
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
    final_dec = Server.decrypt_model(ctx_total, ctx.vector_length)
    new_time = (time.time()-t)#/Server.context.t_threshold
    Server.server_time += new_time
    avg_time += new_time
    print("Server decrypt time: {:.4f} seconds".format(new_time))
    t = time.time()
    # final_dec = p.decode_model(final_dec)
    # load_model(final_dec,global_model)
    avg_time += time.time()-t
    return avg_time

Client.broadcast_pk(Server.encryptor)
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
        
        secagg_time = secure_aggregation_vector(joined,ctx.vector_length)
        train_times.append(train_time)
        secagg_times.append(secagg_time)
    print("SA time: {:.4f}".format(sum(secagg_times)/num_round))
    print("FL+SA time: {:.4f}".format(sum(secagg_times)/num_round + sum(train_times)/num_round))
# round_ciphertexts = []
# for i in range(2):
#     p = Server.servers[i]
#     p.encode_model()
#     ctxs = p.encrypt_model()
#     round_ciphertexts.append(ctxs)
# # print(ctxss[0][0])
# ctx_total = [evaluator.add_many([ciphertext[i] for ciphertext in round_ciphertexts]) for i in range(len(round_ciphertexts[0]))]
# decrypt = p.decrypt_model(ctx_total)
# # print(decrypt)
#     # decrypt=None
# sum_state = p.decode_model(decrypt)
# load_model(sum_state,global_model)
# print(len(Server.servers[0].images))

# print(list(Server.servers[1].model.parameters())[0]*2-list(global_model.parameters())[0])
total_train(1)
print("Server time: {}".format(Server.server_time))#/ctx.n_party))
print("Client time: {}".format(Client.client_time/ctx.n_client))
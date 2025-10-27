import numpy as np
from typing import OrderedDict
from context import Context
from seal import *
from sympy import ntt, intt
import time
import torch

context = Context()
# encoder = BatchEncoder(context.seal_context)

def count_parameters(model):
    return sum(p.numel() for p in model.parameters())

def quantize(float_array, B):
    # return (float_array*B+2**19).round().astype(np.int64)
    return np.mod((float_array*B).round().astype(np.int64),pow(2,20))
def dequantize(int_array, B):
    int_array -= (int_array>pow(2,19))*pow(2,20)
    return int_array/B
    # return (int_array-C*2**19)/B

def polymul(a,b,mod):
    poly_deg = len(a)
    # print(poly_deg)
    a_extend = np.zeros(poly_deg*2-1,dtype=np.int64)
    b_extend = np.zeros(poly_deg*2-1,dtype=np.int64)
    a_extend[:poly_deg] = a
    b_extend[:poly_deg] = b
    a_ntt = np.array(ntt(a_extend,prime=mod))
    b_ntt = np.array(ntt(b_extend,prime=mod))
    ab = np.array(intt(a_ntt*b_ntt,prime=mod))
    ab[:poly_deg] = (ab[:poly_deg] - ab[poly_deg:]) % mod
    return ab[:poly_deg]

def encrypt(x,pub,mod,t):
    c0,c1=pub
    poly_size = len(c0)
    u = np.random.randint(0,2,poly_size,dtype=np.int64)
    e = np.random.randint(0,2,(poly_size,2),dtype=np.int64)
    ctx0 = np.mod(polymul(u,c0,mod)+e[:,0]+int(mod/t)*x,mod)
    ctx1 = (polymul(u,c1,mod)+e[:,1])%mod
    return [ctx0,ctx1]

def partial_decrypt(ctx,sk,mod,t):
    ctx0,ctx1 = ctx
    return np.mod(polymul(ctx1,sk,mod)+ctx0,mod)
    

def decrypt(ctx,sk,mod,t):
    ctx0,ctx1 = ctx
    m = np.mod(polymul(ctx1,sk,mod)+ctx0,mod)
    return ((m.astype('float')*(t/mod)).round()%t).astype(np.int64)

def to_string_encode(poly_vec):
    return encoder.encode(poly_vec)#.to_string()

def to_numpy_decode(hex_string):
    #text = Plaintext(hex_string)
    return encoder.decode(hex_string)

def to_string(poly_vec):
    """_summary_
        Convert a polynomial vector to string
    Args:
        poly_vec (np array): vector representation
    """
    poly_vec = np.array(poly_vec,dtype=np.int64)
    poly_vec = np.mod(poly_vec,0x7e00001)
    return to_string_native(poly_vec.astype(np.uint64),len(poly_vec))

def to_numpy(hex_string):
    try:
        poly_deg = int(hex_string.split()[0].split("x^")[1])
        # print(poly_deg)
    except:
        poly_deg = 0
    poly = Poly(context.seal_context,hex_string)
    return to_numpy_native(poly, poly_deg+1).astype(np.int64)[::-1]

def model_to_flatten_int_vector(model_dict, B=2**16):
    tensors = []
    tensor_position = dict()
    shapes = dict()
    current = 0
    for name, param in model_dict.items():
        x = param.clone()
        ori_shape = x.shape
        shapes[name] = ori_shape
        
        y = x.reshape(-1)
        
        tensor_position[name] = (current,current+y.shape[0])
        tensors.append(y)
        current += y.shape[0]

    tensor_total = torch.cat(tensors)
    device = tensor_total.device
    tensor_total = quantize(tensor_total.cpu().detach().numpy(), B)
    
    return {
        "tensor":tensor_total, 
        "tensor_position":tensor_position, 
        "tensor_shape":shapes,
        "device": device
    }

def flatten_int_vector_to_model(param_info_dict,B=2**16):
    tensor_shapes = param_info_dict['tensor_shape']
    tensor_position = param_info_dict['tensor_position']
    tensor_flatten = param_info_dict['tensor']
    device = param_info_dict['device']
    tensor_flatten = torch.as_tensor(dequantize(tensor_flatten, B)).to(device)
    output_state = OrderedDict()
    for n in tensor_shapes.keys():
        ori_shape = tensor_shapes[n]
        i,j = tensor_position[n]
        y = tensor_flatten[i:j]
        z = y.reshape(ori_shape)
        output_state[n] = z
    return output_state

if __name__=="__main__":
    # x = np.random.randint(0,10,1024,dtype=np.int64)
    # p = to_string(x)
    # q = to_numpy(p)#to_numpy_native(Poly(context.seal_context,p),1024)
    # print(q-x)
    # print(p)
    x = np.random.randint(0,10,1024,dtype=np.int64)
    t = time.time()
    for _ in range(100):
        p = to_string_encode(x)
        q = to_numpy_decode(p)[:len(x)]
    print(x-q,time.time()-t)
    
    t = time.time()
    for _ in range(100):
        p = to_string(x)
        q = to_numpy(p)[:len(x)]
    print(x-q)
    print(time.time()-t)
    # p = Poly(context.seal_context,to_string(x))
    # q = to_numpy_native(p,1024)
    # print(q)
    # x = np.array([0.1,0,0.3])
    # q = quantize(x,100)
    # print(to_string(q),q)
    # q = to_numpy(to_string(q))
    # d = dequantize(q,100)
    # print(d)

    # from model import SimpleConvNet
    # model = SimpleConvNet(1,10)
    # model.to('cuda')
    # state_dict = model.state_dict()
    # info = model_to_flatten_int_vector(state_dict)
    # recon_dict = flatten_int_vector_to_model(info)

    # for name in state_dict.keys():
    #     o = state_dict[name]
    #     r = recon_dict[name]
    #     print((o-r).abs().max())

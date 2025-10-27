# from typing import OrderedDict
# import torch
# from model import *

# model = SimpleConvNet(1,10)

# # print(model.state_dict())
# def model_to_flatten_vector(model_dict):
#     tensors = []
#     tensor_position = dict()
#     shapes = dict()
#     current = 0
#     for name, param in model_dict.items():
#         x = param.clone()
#         ori_shape = x.shape
#         shapes[name] = ori_shape
        
#         y = x.reshape(-1)
        
#         tensor_position[name] = (current,current+y.shape[0])
#         tensors.append(y)
#         current += y.shape[0]

#     tensor_total = torch.cat(tensors)
#     return {
#         "tensor":tensor_total, 
#         "tensor_position":tensor_position, 
#         "tensor_shape":shapes
#     }

# def flatten_vector_to_model(param_info_dict):
#     tensor_shapes = param_info_dict['tensor_shape']
#     tensor_position = param_info_dict['tensor_position']
#     tensor_flatten = param_info_dict['tensor']
#     output_state = OrderedDict()
#     for n in tensor_shapes.keys():
#         ori_shape = tensor_shapes[n]
#         i,j = tensor_position[n]
#         y = tensor_flatten[i:j]
#         z = y.reshape(ori_shape)
#         output_state[n] = z
#     return output_state
    
# ori_state = model.state_dict()
# info = model_to_flatten_vector(ori_state)
# recon_state_dict = flatten_vector_to_model(info)

# for name in ori_state.keys():
#     o = ori_state[name]
#     r = recon_state_dict[name]
#     print(o-r)
from seal import *
from context import Context
import numpy as np

ctx = Context()
x = np.array([1,2,3])
y = Plaintext(x)
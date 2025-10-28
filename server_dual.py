import numpy as np
from tqdm import tqdm
from seal import *

class Server:
    servers = []
    context = None
    
    def __init__(self, id_, context):
        self.id = id_
        self.context = context
        self.seeds = {}
        if Server.context is None:
            Server.context = context
        Server.servers.append(self)
    
    @staticmethod
    def aggregate(ctx_list):
        """服务器只负责聚合密文"""
        evaluator = Evaluator(Server.context.seal_context)
        if len(ctx_list) == 0:
            return []
        
        # 假设所有客户端发送的密文数量相同
        num_ciphertexts = len(ctx_list[0])
        aggregated = []
        
        for i in range(num_ciphertexts):
            ciphertexts_to_add = [ctx[i] for ctx in ctx_list]
            aggregated.append(evaluator.add_many(ciphertexts_to_add))
        
        return aggregated

if __name__=="__main__":
    from context import Context
    ctx = Context()
    
    # 只创建2个服务器
    for i in tqdm(range(2)):
        s = Server(i+1, ctx)
    
    print(f"Created {len(Server.servers)} servers for aggregation")
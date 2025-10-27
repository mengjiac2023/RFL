from seal import *
class Context:
    def __init__(self):
        self.degree = 2048
        self.coeff_mod = 0x3fffffff000001
        self.plain_mod = pow(2,19)#1054721#pow(2,20)#1054721#pow(2,20)#pow(2,16)
        self.t_threshold = 16
        self.n_party = 30
        self.n_client = 100
        parms = EncryptionParameters(scheme_type.bfv)
        parms.set_poly_modulus_degree(self.degree)
        parms.set_coeff_modulus([Modulus(self.coeff_mod)])
        parms.set_plain_modulus(self.plain_mod)
        self.seal_context = SEALContext(parms,True,sec_level_type.none)
        self.vector_length = 1<<20
        self.local_batch_size = 32

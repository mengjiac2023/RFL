import numpy as np
from context import Context

ctx = Context()
share_matrices = np.array([[pow(g,x,ctx.coeff_mod) for x in range(ctx.t_threshold)] for g in range(1,ctx.n_party+1)])
np.save("indices_power.npy",share_matrices)
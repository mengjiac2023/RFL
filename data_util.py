
import struct
import numpy as np
import torch

from torch.utils.data import DataLoader, Dataset

class FedDataset(Dataset):
    def __init__(self, images, labels):
        self.images = images
        self.labels = labels
    def __len__(self):
        return len(self.labels)
    def __getitem__(self, idx):
        return self.images[idx], self.labels[idx]

def read_idx(filename):
    with open(filename, 'rb') as f:
        zero, data_type, dims = struct.unpack('>HBB', f.read(4))
        shape = tuple(struct.unpack('>I', f.read(4))[0] for d in range(dims))
        return np.fromstring(f.read(), dtype=np.uint8).reshape(shape)

def share_data_mnist(n_parties):
    data = read_idx("data/MNIST/raw/train-images-idx3-ubyte")
    label = read_idx("data/MNIST/raw/train-labels-idx1-ubyte")
    dats = [None]*n_parties
    lbls = [None]*n_parties
    for i in range(n_parties):
        dats[i] = torch.Tensor(data[i::n_parties,:,:]).float()/255
        lbls[i] = torch.Tensor(label[i::n_parties]).long()
    return dats, lbls

def unpickle(file):
    import pickle
    with open(file, 'rb') as fo:
        dict = pickle.load(fo, encoding='bytes')
    return dict[b'data'], torch.tensor(dict[b'labels'])
def load_data_cifar(train=True):
    data = []
    label = []
    if train:
        for i in range(1,6):
            pdata, plabel = unpickle(f"/media/tson1997/DATA/backup/cifar-10-batches-py/data_batch_{i}")
            # print(pdata.shape)
            data.append(torch.tensor(pdata,dtype=float))
            label.append(plabel)
    else:
        pdata, plabel = unpickle("/media/tson1997/DATA/backup/cifar-10-batches-py/test_batch")
        data.append(torch.tensor(pdata,dtype=float))
        label.append(plabel)
    data = torch.cat(data)
    label = torch.cat(label)
    return data,label
def share_data_cifar(n_parties):
    data, label = load_data_cifar()
    # print(data.shape)
    dats = [None]*n_parties
    lbls = [None]*n_parties
    for i in range(n_parties):
        dats[i] = data[i::n_parties,:].float()/255
        lbls[i] = label[i::n_parties].long()
    return dats, lbls

if __name__=="__main__":
    data, label = share_data_mnist(1)
    print(data[0].mean(),label[0])
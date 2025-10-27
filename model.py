from torch import nn
import torch.nn.functional as F
import torch

def get_n_params(model):
    pp=0
    for p in list(model.parameters()):
        print(p.size())
        nnn=1
        for s in list(p.size()):
            nnn = nnn*s
        pp += nnn
    return pp

class LogisticRegression(nn.Module):
    def __init__(self, input_dim, output_dim):
        super(LogisticRegression, self).__init__()
        self.linear = nn.Linear(input_dim, output_dim)
        # print(get_n_params(self))
        # exit(0)
    def layers(self):
        return {"linear_weight":self.linear.weight, "linear_bias":self.linear.bias}
    def forward(self, x):
        x = nn.Flatten()(x)
        outputs = torch.sigmoid(self.linear(x))
        return outputs

class Classifier(nn.Module):
    def __init__(self, input_layer=784, layer1=128, layer2=256, output=10):
        super().__init__()
        self.layer1 = nn.Linear(input_layer, layer1)
        self.layer2 = nn.Linear(layer1, layer2)
        self.layer3 = nn.Linear(layer2, output)
        
        # print(get_n_params(self))
        # exit(0)
    def _init_weights(self, module):
        if isinstance(module, nn.Linear):
            module.weight.data.normal_(mean=0.0, std=1.0)
            if module.bias is not None:
                module.bias.data.zero_()
    def layers(self):
        return {"layer1_weight":self.layer1.weight, "layer2_weight":self.layer2.weight, "layer3_weight":self.layer3.weight,
                "layer1_bias":self.layer1.bias, "layer2_bias":self.layer2.bias, "layer3_bias":self.layer3.bias}
    def forward(self,x):
        x = nn.Flatten()(x)
        x = self.layer1(x)
        x = nn.ReLU()(x)
        x = self.layer2(x)
        x = nn.ReLU()(x)
        x = self.layer3(x)
        x = nn.functional.softmax(x)
        return x


class SimpleConvNet(nn.Module):
    def __init__(self, input_dim, output_dim):
        super().__init__()
        self.input_dim = input_dim
        self.conv1 = nn.Conv2d(input_dim, 6, 5)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(6, 16, 5)
        self.fc1 = nn.Linear(16 * 4 * 4, 120)
        self.fc2 = nn.Linear(120, 84)
        self.fc3 = nn.Linear(84, output_dim)
        # print(get_n_params(self))
        # exit(0)
    def forward(self, x):
        x = x.view(-1,self.input_dim,28,28)
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = torch.flatten(x, 1) # flatten all dimensions except batch
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        # print(x.shape)
        return x
        
    def layers(self):
        res = dict()
        for i, module in enumerate(self.parameters()):
            # if isinstance(module,SimpleConvNet):
            res[i] = module
        # print(res)
        # exit(0)
        return res
        
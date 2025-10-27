import matplotlib.pyplot as plt
x = [1000,10000,100000,1000000]
comm_cli = [0.082, 0.82, 8.20, 82.02]
comm_server = [0.09,0.83,8.21,82.03]
comm_leader = [5.48,54.84,548.3, 5483.63]

plt.plot(x,comm_cli,label="client comm",marker="o")
plt.plot(x,comm_server, label="general server",marker="x")
plt.plot(x,comm_leader, label="leader server",marker=".")
plt.xscale("log")
plt.yscale("log")
plt.xlabel("model size")
plt.ylabel("communication (MB)")
plt.legend()
plt.savefig("test.jpg")
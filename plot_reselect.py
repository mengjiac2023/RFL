import matplotlib.pyplot as plt

# Read the data from the file
data = []
with open("reselect_10.txt", "r") as file:
    for line in file:
        x, y = line.strip().split(",")
        data.append((float(x), float(y)))

# Extract x and y values
x_values = [x for x, _ in data]
y_values = [y for _, y in data]

# Create the plot
plt.plot(x_values, y_values, label="Total servers: 10, Threshold: 6")

data = []
with open("reselect_15.txt", "r") as file:
    for line in file:
        x, y = line.strip().split(",")
        data.append((float(x), float(y)))

# Extract x and y values
x_values = [x for x, _ in data]
y_values = [y for _, y in data]

# Create the plot
plt.plot(x_values, y_values, label="Total servers: 15, Threshold: 8")

data = []
with open("reselect_20.txt", "r") as file:
    for line in file:
        x, y = line.strip().split(",")
        data.append((float(x), float(y)))

# Extract x and y values
x_values = [x for x, _ in data]
y_values = [y for _, y in data]

# Create the plot
plt.plot(x_values, y_values, label="Total servers: 20, Threshold: 11")

data = []
with open("reselect_30.txt", "r") as file:
    for line in file:
        x, y = line.strip().split(",")
        data.append((float(x), float(y)))

# Extract x and y values
x_values = [x for x, _ in data]
y_values = [y for _, y in data]

# Create the plot
plt.plot(x_values, y_values, label="Total servers: 30, Threshold: 16")



# plt.xlabel("malicious probability")
# plt.ylabel("average number of reselections")
plt.legend()
plt.savefig("reselect.pdf")

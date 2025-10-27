# Mario
Implementation of the paper "Mario: Multi-round Multiple-Aggregator Secure Aggregation with Robustness against Malicious Actors"

Setup
```
# Install dependencies
pip3 install numpy pybind11

# Init pybind11
git submodule update --init --recursive
# Get the newest repositories (dev only)
# git submodule update --remote

# Build the SEAL lib without the msgsl zlib and zstandard compression
cd SEAL
cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build build
cd ..

# Run the setup.py, the dynamic library will be generated in the current directory
python3 setup.py build_ext -i
```

Run
```
python main.py
```

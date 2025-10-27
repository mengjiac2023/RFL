python setup.py build_ext -i
cp seal.*.so examples
cd examples
python test.py
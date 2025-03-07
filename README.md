# FHE Tests

## Installation Instructions
* Install Python 3.12.8
* Create a virtual environment named `.vnv12`
* Follow [OpenFHE-Development download instructions](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html) 
    *  git clone https://github.com/openfheorg/openfhe-development.git
    * cd openfhe-development
    * mkdir build
    * cd build
    * cmake -DPYTHON_EXECUTABLE_PATH="$(which python)" ..
    * make -j1
    * sudo make install
    * cd ../..
* `python -m pip install -r requirements.txt`
* `pytest`
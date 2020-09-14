# [Linear Private Function Evaluation](https://encrypto.de/papers/HKRS20.pdf) [![Build Status](https://travis-ci.org/encryptogroup/linearPFE.svg?branch=public)](https://travis-ci.org/encryptogroup/linearPFE)

By Marco Holz¹, Ágnes Kiss¹, Deevashwer Rathee², and Thomas Schneider¹. (¹ [ENCRYPTO](http://www.encrypto.de), TU Darmstadt; ² [Department of Computer Science](https://iitbhu.ac.in/dept/cse), IIT (BHU) Varanasi)<br>In [European Symposium on Research in Computer Security (ESORICS'20)](https://www.surrey.ac.uk/esorics-2020). [Paper available here.](https://encrypto.de/papers/HKRS20.pdf)

This work is based on the [ABY framework for efficient mixed-protocol secure two-party computation](https://github.com/encryptogroup/ABY/).

For simplicity, we will only describe the short version of the build process here, including the differences and additional steps required compared to the ABY build procedure.
Please also refer to the detailed build instructions of ABY.

## Additional build requirements
In addition to the build requirements of ABY, you need to install the following software in advance:

- [Microsoft SEAL](https://github.com/microsoft/SEAL) is used for BFV homomorphic encryption. Please refer to the SEAL installation instructions.

## Build Instructions (Short Version)

1. Clone the git repository by running:
    ```
    git clone https://github.com/encryptogroup/linearPFE.git
    ```

2. Enter the Framework directory: `cd linearPFE/`

3. Enter the build directory: `cd build`

4. Use CMake configure the build (using only one of the two different `cmake` commands).
    Assuming you globally installed SEAL:
    ```
    cmake ..
    ```

    Assuming you locally installed SEAL in the `~/mylibs` directory:
    ```
    cmake -DCMAKE_PREFIX_PATH=~/mylibs ..
    ```

    This also initializes and updates the Git submodules of the dependencies
    located in `extern/`.  If you plan to work without a network connection,
    you should to a `--recursive` clone in Step 1.

5. Call `make` in the build directory.
   You can find the build executables and libraries in the directories `bin/`
   and `lib/`, respectively.

## Running PFE performance measurements

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

Prior to running the performance measurements, choose the HE scheme in `src/abycore/sharing/yaosharing.h`:
```
// choose between DJN/Paillier, RLWE-based (BFV) or ECC-based (EC ElGamal) encryption
#define KM11_CRYPTOSYSTEM_DJN 1
#define KM11_CRYPTOSYSTEM_BFV 2
#define KM11_CRYPTOSYSTEM_ECC 3
#define KM11_CRYPTOSYSTEM KM11_CRYPTOSYSTEM_ECC // <-- set the HE scheme of you choice here
```

If you want to disable parallelized multi-core execution, you may disable OpenMP in the `CMakeLists.txt` file in the root directory of the project:
```
# Remove/comment the following lines to disable OpenMP parallel execution
find_package(OpenMP)
if(OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()
```

After changing these lines, make sure to re-run `cmake` and `make` (see build instruction) to apply the changes.

Inside the build directory, you can find two helper scripts to run and evaluate the experiments:
- `./build/run_PFE_perf.sh` can be used to execute the performance measurements. Please run `./run_PFE_perf.sh 0` to start the server (holding the private input x) and run `./run_PFE_perf.sh 1` to start the client (holding the private function f). See the comments inside the script on how to run the performance tests between two independent machines. The script will automatically run 10 iterations with circuits of size 1000, 10000, 100000 and 1000000 gates each.
- `./build/eval_PFE_perf.py` can be used to evaluate the measurements created by the previous script. List the measurement files usung `ls` and run `python eval_PFE_perf.py perf_2020_01_01-1337`, where `perf_2020_01_01-1337` is the prefix of the measurement files, to create csv files with containing the averaged performance measurements. The script will automatically detect the HE scheme and will name the csv files (created in the current directory) accordingly.

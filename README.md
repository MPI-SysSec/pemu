# pemu-ae
## Structure
- `src/`: Contains the standalone source code of PEMU
- `scripts/`: Contains useful scripts for the evaluation
- `rehosting_platforms/`: Contains the evaluated rehosting platforms, and patches to prepare them for the use with PEMU
- `eval/`: Contains the sources and targets for the evaluation

## Setup
First, run `git submodule update --init --recursive`.   
Next, go to `eval/01-coverage-experiments/nrf52840/nuttx_nimble` and run `unzip nuttx.zip` (One of the binaries is too large for github).


Our tool serves as an add-on for existing rehosting platforms. For this paper we attached PEMU to three platforms: SEmu, Fuzzware, and Hoedur.  
This section describes how to setup everything for further fuzzing.  
After setting up a rehosting platform, all attached data and scripts can be found in `rehosting_platforms/<platform>`

### SEmu
To setup SEmu for fuzzing execute the script `/scripts/setup_semu.sh`. This script sets up two versions of SEmu, one with PEMU and one without.
It then builds docker containers for both versions

### Fuzzware
To setup SEmu for fuzzing execute the script `/scripts/setup_semu.sh`. This script sets up fuzzware to be able to use PEMU.

### Hoedur
To setup Hoedur for fuzzing you need to execute the script `scripts/setup_hoedur.sh`.
This script builds a dedicated docker container that contains all of the hoedur ablations used in the paper.  


## Running the Eval
The evaluation for PEMU consists of three main parts:
- coverage experiments
- bug rediscovery experiments
- fuzzing beyond network stacks: industrial example

To run everything, the script `scripts/run_experiments.sh` can be used. Otherwise the scripts in `scripts/run_scripts/` can be consulted to run individual aspects of the evaluation.

Results can be found:
- `fuzzware`: fuzzware project dirs are placed in the eval tree
- `hoedur`: in `rehosting_platforms/hoedur/` you can find the corpus dirs
- `semu`: results can be found in `rehosting_platforms/SEmu-Fuzz*/results`


## Further Data
The directory `eval/04-bug-reports` contains reports of some of the bugs discussed in the paper.

## Roadmap/TODOs
In this state the artifact could be considered functional by an artifact review. Currently missing are data aggregation and visualization scripts.
I plan to publish them as well at some point.  
Further, I plan to add more bug writeups at some point.

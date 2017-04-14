# Source and datasets for: "Non-cooperative 802.11 MAC layer fingerprinting and tracking of mobile devices"
This repository contains the source code and links to the datasets used in the paper entitled "Non-cooperative 802.11 MAC layer fingerprinting and tracking of mobile devices". Please cite the paper and / or datasets if you use them in your research.

## Installing the dataset
The MongoDB dataset and usage instructions can be found at [https://zenodo.org/record/545970](https://zenodo.org/record/545970).

An identical ```.pcap``` version of the dataset can be found at [CRAWDAD](http://crawdad.org/).

## Running experiments
After installing the dataset, you can run the experiments using the ```elt_byte_uniqueness.py``` script:

    usage: elt_byte_uniqueness.py [-h] [--host HOST] [--debug] [--big-endian]
                                  [--train-samples NUM_TRAIN_SAMPLES]
                                  [--test-samples NUM_TEST_SAMPLES]
                                  [--threshold THRESHOLD]
                                  {mongodb,file,pcap} {mac_info,mac_research}

    Advanced MAC layer fingerprinter for Probe Request frames

    positional arguments:
      {mongodb,file,pcap}
      {mac_info,mac_research}
                            The path to / name of the dataset containing Probe
                            Requests

    optional arguments:
      -h, --help            show this help message and exit
      --host HOST           MongoDB host (default: localhost)
      --debug, -d           Debug mode (default: False)
      --big-endian          Big Endian Radiotap header (default: False)
      --train-samples NUM_TRAIN_SAMPLES
                            Number of training samples (default: 30000)
      --test-samples NUM_TEST_SAMPLES
                            Number of test samples (default: 50)
      --threshold THRESHOLD
                            Stability threshold (default: 0.3)

## Examples

Using the default settings: training on 30000 and testing on 50 devices:

    $ ./elt_byte_uniqueness.py --host <your_mongo_database> mongodb mac_info
    ...
    Strict hash stability: 100.0%
    Real hash stability: 100.0%
    Real hash stability (non-random): 100.0%
    Hash uniqueness: 78.0%
    Hash uniqueness (non-random): 82.5%
    Fingerprint uniqueness: 94.0%
    Deanonymized MACs: 1 / 10.0 (10.0%)
    Total MACs: 50.0

Other test set sizes:

    $ ./elt_byte_uniqueness.py --host <your_mongo_database> --test-samples 1000 mongodb mac_info
    ...
    Strict hash stability: 99.7%
    Real hash stability: 99.85%
    Real hash stability (non-random): 99.7716894977%
    Hash uniqueness: 28.9%
    Hash uniqueness (non-random): 39.1171993912%
    Fingerprint uniqueness: 79.5%
    Deanonymized MACs: 111 / 343.0 (32.361516035%)
    Total MACs: 1000.0

    $ ./elt_byte_uniqueness.py --host <your_mongo_database> --test-samples 10000 mongodb mac_info
    ...
    Strict hash stability: 91.34%
    Real hash stability: 95.9216190476%
    Real hash stability (non-random): 94.5693699166%
    Hash uniqueness: 10.66%
    Hash uniqueness (non-random): 17.2218284904%
    Fingerprint uniqueness: 97.07%
    Deanonymized MACs: 4006 / 4356.0 (91.9651056015%)
    Total MACs: 10000.0

Using the ```mac_research``` dataset:

    $ ./elt_byte_uniqueness.py --host <your_mongo_database> --test-samples 100 --train-samples 100 --threshold 1.0 mongodb mac_research
    Using research center data
    ...
    Strict hash stability: 93.3333333333%
    Real hash stability: 98.5609279609%
    Real hash stability (non-random): 98.3395322626%
    Hash uniqueness: 50.6666666667%
    Hash uniqueness (non-random): 55.3846153846%
    Fingerprint uniqueness: 100.0%
    Deanonymized MACs: 10 / 10.0 (100.0%)
    Total MACs: 75.0

## Explanation of metrics
After running ```elt_byte_uniqueness.py```, several metrics are displayed to the user, which have the following meaning:

* Strict hash stability           : Average ratio of devices with a stable hash to all devices
* Real hash stability             : Average ratio of most prominent hash to to all hashes for each device
* Real hash stability (non-random): Average ratio of most prominent hash to to all hashes for each device with non-random MAC
* Hash uniqueness                 : Ratio of unique IE hashes to all IE hashes for random MACs
* Hash uniqueness (non-random)    : Ratio of unique IE hashes to all IE hashes for non-random MACs
* Fingerprint uniqueness          : Ratio of unique fingerprints to all fingerprints
* Deanonymized MACs               : Number of random MACs successfully mapped to non-random MACs
* Total MACs                      : Number of unique MAC addresses in test set

Here, the term "hash" refers to the hash of the bitmask applied to the Information Elements of the Probe Request, and the term "fingerprint" refers to the associated fingerprint (which can include the non-random MAC address as well if available).

## Paper experiments
The exact parameters used in the paper can be found in the ```compare_runs_lambda_small``` and ```compare_runs_lambda``` functions of the source code. These functions generate the GNUplot output for the graphs. Note that results might slightly vary due to the anonymization process that was performed on the dataset (e.g. stable bits in the WPS IE for some devices).

/*
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contract No. N66001-11-C-4017.
 *
 * Copyright 2014 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <click/config.h>
#include "bloomaccesstest.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/timestamp.hh>
#include <fcntl.h>
#include <unistd.h>
CLICK_DECLS


BloomAccessTest::BloomAccessTest()
{
}


BloomAccessTest::~BloomAccessTest()
{
}

int
BloomAccessTest::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "BLOOMFILE", 0, cpFilename, &_bloom_file,
                        cpEnd);
}

int
BloomAccessTest::initialize(ErrorHandler *errh)
{
    // LOAD BLOOM FILTER
    errh->message("Loading bloom filter...");

    fprintf(stdout, "opening bloom filter %s\n", _bloom_file.c_str());

    if (!read_bloom_filter()) {
        errh->message("Failed to read bloom filter.");
        return 0;
    }

    fprintf(stdout, "Hash size: %u\n", _bloom_filter.hash_size());
    fprintf(stdout, "Num salts: %u\n", _bloom_filter.salt_values().size());

    // GENERATE RANDOM SENTINELS
    errh->message("Generating sentinels...");

    for (int i = 0; i < NTRIALS; ++i) {
        for (int j = 0; j < 8; ++j) {
            _sentinels[i][j] = (char) (rand() & 0xff);
        }
    }

    // TESTING SENTINEL MEMBERSHIP
    errh->message("Testing sentinel membership...");

    // record start time
    Timestamp start = Timestamp::now();

    for (int i = 0; i < NTRIALS; ++i) {
        if (_bloom_filter.member(_sentinels[i], 8)) {
	    fprintf(stdout, "matched!\n");
	}
    }

    // record stop time
    Timestamp end = Timestamp::now();

    // REPORT RESULTS
    errh->message("Generating results...");

    Timestamp elapsed = end - start;
    fprintf(stdout, "Elapsed time: %s\n", elapsed.unparse().c_str());
    fprintf(stdout, "Trials/s: %f\n", NTRIALS / elapsed.doubleval());

    // SUCCESS
    errh->message("All done!");
    return 0;
}

bool
BloomAccessTest::read_bloom_filter(void)
{
    if (_bloom_file.length() == 0) {
        click_chatter("No bloom file specified.");
        return false;
    }

    int fd = open(_bloom_file.c_str(), O_RDONLY);
    if (fd < 0) {
        click_chatter("Failed to open bloom file %s.", _bloom_file.c_str());
        return false;
    }

    uint8_t buf[256];

    // skip over the first 40 bytes of the file
    if (read(fd, buf, 40) != 40) {
        click_chatter("Error skipping over header.");
        return false;
    }

    // read the specified hash size
    uint64_t hash_size = 0;
    if (read(fd, &hash_size, 8) != 8) {
        click_chatter("Error reading hash size.");
        return false;
    }

    // read the number of salts
    uint32_t  num_salts = 0;
    if (read(fd, &num_salts, 4) != 4) {
        click_chatter("Error reading the number of salt values.");
        return false;
    }

    // read the salt values
    Vector<uint32_t> salt_values;
    for (int i = 0; i < num_salts; ++i) {
        uint32_t salt_value;
        if (read(fd, &salt_value, 4) != 4) {
            click_chatter("Error reading salt value.");
            return false;
        }
        salt_values.push_back(salt_value);
    }

    // read the bit vector
    int total_bits = BloomFilter::bit_vector_size(hash_size);
    Bitvector bit_vector(total_bits);
    uint32_t *bit_data = bit_vector.words();

    int read_bytes;
    int remaining_bytes = ((total_bits < 8)? 1 : (total_bits / 8));

    while(remaining_bytes > 0) {

        read_bytes = read(fd, buf, 256);
        if (read_bytes < 0) {
            click_chatter("Error reading filter.");
            return false;

        } else if (read_bytes == 0) {
            click_chatter("Filter too small.");
            return false;

        } else if (read_bytes > remaining_bytes) {
            click_chatter("Filter too large.");
            return false;
        }

        memcpy(bit_data, buf, read_bytes);

        bit_data += (read_bytes / 4);
        remaining_bytes -= read_bytes;
    }

    assert(remaining_bytes == 0);
    assert(fd >= 0);
    close(fd);

    // successfully read bloom filter from file
    _bloom_filter = BloomFilter(hash_size, bit_vector, salt_values);
    return true;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(BloomAccessTest)

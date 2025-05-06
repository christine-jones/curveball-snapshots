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
#include "dr2dpdecodertest.hh"
#include "dr2dpdecoder.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/integers.hh>
CLICK_DECLS


DR2DPDecoderTest::DR2DPDecoderTest()
{
}

DR2DPDecoderTest::~DR2DPDecoderTest()
{
}

int
DR2DPDecoderTest::initialize(ErrorHandler *errh)
{
    dr2dp_msg hdr;
    Packet *p = NULL;
 
    bzero(&hdr, sizeof(dr2dp_msg));

    //
    // Base DR2DP message header.
    //
    errh->message("*** DR2DP Message Header Tests ***");

    // Invalid protocol version.
    p = WritablePacket::make(&hdr, sizeof(dr2dp_msg));
    output(0).push(p);

    // Unsupported operation type.
    hdr.protocol = DR2DP_PROTOCOL_VERSION;
    hdr.data_length = htonq(0);
  
    p = WritablePacket::make(&hdr, sizeof(dr2dp_msg));
    output(0).push(p);

    // Invalid message type.
    hdr.operation_type = DR2DP_OP_TYPE_FORWARD;

    p = WritablePacket::make(&hdr, sizeof(dr2dp_msg));
    output(0).push(p);

    // Valid message.
    String data("This is a test.");
    hdr.message_type = DR2DP_MSG_TYPE_REQUEST;
    hdr.data_length = htonq(data.length());
    String packet((const char *)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    //
    // Message buffers.
    //
    errh->message("*** DR2DP Message Buffer Tests ***");

    // Multiple messages in single packet.
    packet.append((const char *)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());
    packet.append((const char *)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    // Single message in multiple packets.
    hdr.data_length = htonq(3 * data.length());
    packet = String((const char*)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    // Mixed buffers.
    hdr.data_length = htonq(data.length());
    packet = String((const char*)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());
    hdr.data_length = htonq(3 * data.length());
    packet.append((const char *)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(data.data(), data.length());
    hdr.data_length = htonq(2 * data.length());
    packet.append((const char *)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(data.data(), data.length());
    hdr.data_length = htonq(data.length());
    packet.append((const char*)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());
    packet.append((const char*)&hdr, sizeof(dr2dp_msg));
    packet.append(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    // DR2DP message header spans multiple buffers.
    packet = String((const char *)&hdr, 12);

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(((const char *)&hdr + 12), 12);

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    packet = String(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    char * cur_pos = (char *)&hdr;
    for (int i = 0; i < 24; ++i) {
        packet = String(cur_pos, 1);
        ++cur_pos;

        p = WritablePacket::make(packet.data(), packet.length());
        output(0).push(p);
    }

    packet = String(data.data(), data.length());

    p = WritablePacket::make(packet.data(), packet.length());
    output(0).push(p);

    //
    // Filter Message
    //
    errh->message("*** DR2DP Filter Message Tests ***");

    dr2dp_filter_msg filter_hdr;
    bzero(&filter_hdr, sizeof(dr2dp_filter_msg));

    hdr.operation_type = DR2DP_OP_TYPE_SENTINEL_FILTER;

    // Invalid data length.
    String invalid_data("ab");
    hdr.data_length = htonq(invalid_data.length());
    String fpkt((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append(invalid_data.data(), invalid_data.length());

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Invalid salt length.
    hdr.data_length = htonq(sizeof(dr2dp_filter_msg));
    filter_hdr.num_salts = htons(2);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Hash size of 0.
    filter_hdr.num_salts = htons(0);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Invalid hash size.
    filter_hdr.hash_size = htons(32);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);


    // Invalid table size; table too small.
    hdr.data_length = htonq(sizeof(dr2dp_filter_msg));
    filter_hdr.hash_size = htons(24);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Invalid table size; table too large.
    hdr.data_length = htonq(sizeof(dr2dp_filter_msg));
    filter_hdr.hash_size = htons(2);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Valid table with hash size 18.
    hdr.data_length = htonq(sizeof(dr2dp_filter_msg));
    filter_hdr.hash_size = htons(18);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // Valid salt values.
    uint32_t salt1 = htonl(11375), salt2 = htonl(415);
    hdr.data_length = htonq(sizeof(dr2dp_filter_msg) + 2 * sizeof(uint32_t));
    filter_hdr.hash_size = htons(18);
    filter_hdr.num_salts = htons(2);
    fpkt = String((const char *)&hdr, sizeof(dr2dp_msg));
    fpkt.append((const char *)&filter_hdr, sizeof(dr2dp_filter_msg));
    fpkt.append((const char *)&salt1, sizeof(uint32_t));
    fpkt.append((const char *)&salt2, sizeof(uint32_t));

    p = WritablePacket::make(fpkt.data(), fpkt.length());
    output(0).push(p);

    // DH Blacklist

    bzero(&hdr, sizeof(dr2dp_msg));
    hdr.protocol = DR2DP_PROTOCOL_VERSION;
    hdr.operation_type = DR2DP_OP_TYPE_DH_BLACKLIST;
    hdr.message_type = DR2DP_MSG_TYPE_REQUEST;

    p = WritablePacket::make(&hdr, sizeof(dr2dp_msg));
    output(0).push(p);

    // All done!
    errh->message("All tests passed!");

    return 0;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(DR2DPDecoderTest)

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
#include "sockettest.hh"
#include "dr2dpprotocol.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet.hh>
#include <click/packet_anno.hh>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/un.h>
CLICK_DECLS


SocketTest::SocketTest()
    : _fd(-1), _active(-1), _load_sentinels(false)
{
}

SocketTest::~SocketTest()
{
}

int
SocketTest::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
                        "PATH", 0, cpString, &_pathname,
                        "SENTINELS", 0, cpBool, &_load_sentinels,
                        cpEnd);
}

int
SocketTest::initialize(ErrorHandler *errh)
{
    if (_pathname.length() <= 0) {
        errh->message("pathname not configured");
        return 0;
    }

    _fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_fd < 0) {
        errh->message("failed to create socket");
        _fd = -1;
        return 0;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, _pathname.c_str());

    if (bind(_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        errh->message("failed to bind socket");
        close(_fd);
        _fd = -1;
        return 0;
    }

    if (listen(_fd, 1) < 0) {
        errh->message("failed to listen on socket");
        close(_fd);
        _fd = -1;
        return 0;
    }

    fcntl(_fd, F_SETFL, O_NONBLOCK);
    fcntl(_fd, F_SETFD, FD_CLOEXEC);

    add_select(_fd, SELECT_READ);

    return 0;
}

void
SocketTest::cleanup(CleanupStage)
{
    if (_active >= 0) {
        close(_active);
        _active = -1;
    }

    if (_fd >= 0) {
        close(_fd);
        _fd = -1;
    }
}

void
SocketTest::push(int, Packet *p)
{
    assert(_active >= 0);

    int len = write(_active, p->data(), p->length());
    if (len < 0) {
        click_chatter("SocketTest:push:: failed to write packet");
    }

    p->kill();
}

void
SocketTest::selected(int fd, int)
{
    if (fd == _fd) {
        assert(_active == -1);

        struct sockaddr_un addr;
        socklen_t addr_len = sizeof(struct sockaddr_un);

        _active = accept(_fd, (struct sockaddr *)&addr, &addr_len);
        if (_active < 0) {
            click_chatter("SocketTest::selected:: failed to connect");
        }

        fcntl(_active, F_SETFL, O_NONBLOCK);
        fcntl(_active, F_SETFD, FD_CLOEXEC);

        add_select(_active, SELECT_READ);

        if (_load_sentinels) {
            load_sentinels();
        }

        return;
    }

    assert(fd == _active);

    int len, snaplen = 2048;

    WritablePacket *p = Packet::make(Packet::default_headroom, 0, snaplen, 0);
    if (p == NULL) {
        click_chatter("SocketTest::selected: failed to create packet");
        return;
    }

    len = read(_active, p->data(), p->length());
    if (len < 0) {
        click_chatter("SocketTest::selected: failed to read socket");
        remove_select(_active, SELECT_READ);
        close(_active);
        _active = -1;
        p->kill();
        return;
    }

    if (len > snaplen) {
        click_chatter("SocketTest::selected: snaplen exceeded");
        assert(p->length() == (uint32_t)snaplen);
        SET_EXTRA_LENGTH_ANNO(p, len - snaplen);

    } else {
        p->take(snaplen - len);
    }

    output(0).push(p);
}

void
SocketTest::load_sentinels()
{
    int pkt_len = sizeof(dr2dp_msg) + sizeof(dr2dp_filter_msg);

    WritablePacket *p = WritablePacket::make(pkt_len);
    if (!p) {
        click_chatter("SocketTest::load_sentinels: failed to allocate packet");
        return;
    }

    dr2dp_msg *msg = reinterpret_cast<dr2dp_msg *>(p->data());
    msg->protocol = DR2DP_PROTOCOL_VERSION;
    msg->session_type = 0;
    msg->message_type = DR2DP_MSG_TYPE_REQUEST;
    msg->operation_type = DR2DP_OP_TYPE_SENTINEL_FILTER;
    msg->response_code = 0;
    msg->xid = 0;
    msg->data_length = htonq(sizeof(dr2dp_filter_msg));

    dr2dp_filter_msg *filter_msg =
        reinterpret_cast<dr2dp_filter_msg *>(p->data() + sizeof(dr2dp_msg));
    filter_msg->hash_size = htons(19);
    filter_msg->num_salts = 0;

    int len = write(_active, p->data(), p->length());
    if (len < 0) {
        click_chatter("SocketTest:load_sentinels:: failed to write packet");
    }

    p->kill();
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(SocketTest)

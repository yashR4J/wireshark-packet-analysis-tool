
#include <catch.h>
#include "lib/net.h"
#include "lib/teams.h"
#include "lib/pcap_util.h"
#include "lib/pcap_file_reader.h"
#include "lib/simple_binary_writer.h"
#include "lib/simple_binary_reader.h"

#include "test_packets.h"

TEST_CASE("teams::pkt: is initialized with empty fields", "[teams][pkt]") {

    teams::pkt p;

    CHECK(p.ts.s == 0);
    CHECK(p.ts.us == 0);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 0);
    CHECK(p.flags.rtp == 0);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 0);

    CHECK(p.teams_srv_type == 0);
    CHECK(p.teams_media_type == 0);
    CHECK(p.pkts_in_frame == 0);
    CHECK(p.udp_pl_len == 0);

    CHECK(p.ip_5t.ip_src == 0);
    CHECK(p.ip_5t.ip_dst == 0);
    CHECK(p.ip_5t.tp_src == 0);
    CHECK(p.ip_5t.tp_dst == 0);
    CHECK(p.ip_5t.ip_proto == 0);

    CHECK(p.proto.rtp.ssrc == 0);
    CHECK(p.proto.rtp.ts == 0);
    CHECK(p.proto.rtp.seq == 0);
    CHECK(p.proto.rtp.pt == 0);

    CHECK(p.rtp_ext1[0] == 0);
    CHECK(p.rtp_ext1[1] == 0);
    CHECK(p.rtp_ext1[2] == 0);

    CHECK(p.proto.rtcp.ssrc == 0);
    CHECK(p.proto.rtcp.pt == 0);

    CHECK(sizeof(p) == 56);
}

TEST_CASE("teams::pkt: can be initialized from rtp headers", "[teams][pkt]") {

    auto h = teams::parse_teams_pkt_buf(test::teams_srv_video_buf, true, false);
    teams::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 1);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 1);

    CHECK(p.proto.rtp.ssrc == 16779265);
    CHECK(p.proto.rtp.ts == 4092042800);
    CHECK(p.proto.rtp.seq == 7715);
    CHECK(p.proto.rtp.pt == 98);
}

TEST_CASE("teams::pkt: can be initialized from rtcp headers", "[teams][pkt]") {

    auto h = teams::parse_teams_pkt_buf(test::teams_srv_rtcp_buf, true, false);
    teams::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 0);
    CHECK(p.flags.rtcp == 1);
    CHECK(p.flags.to_srv == 1);
    CHECK(p.flags.from_srv == 0);

    CHECK(p.proto.rtcp.ssrc == 16778242);
    CHECK(p.proto.rtcp.pt == 200);

    CHECK(p.proto.rtcp.rtp_ts == 11336480);
    CHECK(p.proto.rtcp.ntp_ts_msw == 3841332067);
    CHECK(p.proto.rtcp.ntp_ts_lsw == 2542320776);
}

TEST_CASE("teams::pkt: can be initialized from rtp buffers with short format", "[teams][pkt]") {

    auto h = teams::parse_teams_pkt_buf(test::teams_srv_video_short_buf, true, false);
    teams::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 1);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 1);

    CHECK(p.proto.rtp.ssrc == 16779266);
    CHECK(p.proto.rtp.pt == 98);
    CHECK(p.proto.rtp.ts == 740115488);
    CHECK(p.proto.rtp.seq == 1587);
}

TEST_CASE("teams::pkt: can be initialized with a pcap packet ", "[teams][pkt]") {

    pcap_file_reader pcap_reader("data/teams_test.pcap");
    pcap_pkt pcap_pkt;

    pcap_reader.next(pcap_pkt);

    auto hdr = teams::parse_teams_pkt_buf(pcap_pkt.buf, true, true);
    teams::pkt teams_pkt(hdr, pcap_pkt.ts, true);

    CHECK(teams_pkt.ts.s == 1632344358);
    CHECK(teams_pkt.ts.us == 611365);
    CHECK(teams_pkt.flags.p2p == 1);
    CHECK(teams_pkt.flags.srv == 0);
    CHECK(teams_pkt.flags.to_srv == 0);
    CHECK(teams_pkt.flags.from_srv == 0);

    CHECK(teams_pkt.ip_5t.ip_src == 0xa09791c);
    CHECK(teams_pkt.ip_5t.ip_dst == 0xa094aac);
    CHECK(teams_pkt.ip_5t.tp_src == 50508);
    CHECK(teams_pkt.ip_5t.tp_dst == 64904);
    CHECK(teams_pkt.ip_5t.ip_proto == 17);

    CHECK(teams_pkt.udp_pl_len == 1263);

    CHECK(teams_pkt.teams_srv_type == 0);
    CHECK(teams_pkt.teams_media_type == 16);
    CHECK(teams_pkt.pkts_in_frame == 13);

    CHECK(teams_pkt.flags.rtp == 1);
    CHECK(teams_pkt.flags.rtcp == 0);

    CHECK(teams_pkt.proto.rtp.ssrc == 16778241);
    CHECK(teams_pkt.proto.rtp.ts == 4215577188);
    CHECK(teams_pkt.proto.rtp.seq == 26342);
    CHECK(teams_pkt.proto.rtp.pt == 98);

    CHECK(teams_pkt.rtp_ext1[0] == 0x50);
    CHECK(teams_pkt.rtp_ext1[1] == 0x00);
    CHECK(teams_pkt.rtp_ext1[2] == 0x00);
}

TEST_CASE("teams::pkt: can be written to and read from a file", "[teams][pkt]") {

    simple_binary_writer<teams::pkt> zpkt_writer("data/teams_test.zpkt");
    pcap_file_reader pcap_reader("data/teams_test.pcap");
    pcap_pkt pcap_pkt;

    while (pcap_reader.next(pcap_pkt)) {

        auto hdr = teams::parse_teams_pkt_buf(pcap_pkt.buf, true, true);
        teams::pkt zpkt(hdr, pcap_pkt.ts, true);
        zpkt_writer.write(zpkt);
    }

    pcap_reader.close();
    zpkt_writer.close();

    simple_binary_reader<teams::pkt> zpkt_reader("data/teams_test.zpkt");
    teams::pkt teams_pkt;

    CHECK(zpkt_reader.size() == 64);

    unsigned read_count = 0;

    while (zpkt_reader.next(teams_pkt)) {
        read_count++;

        if (read_count == 1) {
            CHECK(teams_pkt.ts.s == 1632344358);
            CHECK(teams_pkt.ts.us == 611365);
            CHECK(teams_pkt.flags.p2p == 1);
            CHECK(teams_pkt.flags.srv == 0);
            CHECK(teams_pkt.flags.to_srv == 0);
            CHECK(teams_pkt.flags.from_srv == 0);

            CHECK(teams_pkt.ip_5t.ip_src == 0xa09791c);
            CHECK(teams_pkt.ip_5t.ip_dst == 0xa094aac);
            CHECK(teams_pkt.ip_5t.tp_src == 50508);
            CHECK(teams_pkt.ip_5t.tp_dst == 64904);
            CHECK(teams_pkt.ip_5t.ip_proto == 17);

            CHECK(teams_pkt.udp_pl_len == 1263);

            CHECK(teams_pkt.teams_srv_type == 0);
            CHECK(teams_pkt.teams_media_type == 16);
            CHECK(teams_pkt.pkts_in_frame == 13);

            CHECK(teams_pkt.flags.rtp == 1);
            CHECK(teams_pkt.flags.rtcp == 0);

            CHECK(teams_pkt.proto.rtp.ssrc == 16778241);
            CHECK(teams_pkt.proto.rtp.ts == 4215577188);
            CHECK(teams_pkt.proto.rtp.seq == 26342);
            CHECK(teams_pkt.proto.rtp.pt == 98);

            CHECK(teams_pkt.rtp_ext1[0] == 0x50);
            CHECK(teams_pkt.rtp_ext1[1] == 0x00);
            CHECK(teams_pkt.rtp_ext1[2] == 0x00);
        }
    }

    CHECK(read_count == 64);
}

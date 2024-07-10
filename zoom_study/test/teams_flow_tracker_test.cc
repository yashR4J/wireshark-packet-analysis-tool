
#include <catch.h>
#include "lib/net.h"
#include "lib/teams_flow_tracker.h"

TEST_CASE("teams::flow_tracker", "[teams][flow_tracker]") {

    SECTION("does not track non-teams flows") {

        net::ipv4_5tuple non_teams_tcp_flow {
                net::ipv4::str_to_addr("98.52.6.140"), net::ipv4::str_to_addr("84.202.2.49"),
                24242, 8801, 6
        };

        net::ipv4_5tuple non_teams_udp_flow {
                net::ipv4::str_to_addr("128.52.6.140"), net::ipv4::str_to_addr("84.202.2.49"),
                24242, 8809, 17
        };

        teams::flow_tracker t;
        CHECK_FALSE(t.track(non_teams_tcp_flow, {1, 0}, 100));
        CHECK_FALSE(t.track(non_teams_udp_flow, {2, 0}, 100));
        CHECK(t.count_teams_flows_detected() == 0);
        CHECK(t.count_total_pkts_processed() == 2);
        CHECK(t.count_teams_pkts_detected() == 0);
    }

    SECTION("tracks teams server flows") {

        net::ipv4_5tuple teams_tcp_flow {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("209.9.215.34"),
                12433, 443, 6
        };

        net::ipv4_5tuple teams_udp_srv_flow {
                net::ipv4::str_to_addr("13.52.6.140"), net::ipv4::str_to_addr("10.0.0.5"),
                8805, 10293, 17
        };

        teams::flow_tracker t;

        auto f1 = t.track(teams_tcp_flow, {1, 0}, 100);
        CHECK(f1);
        CHECK(f1->id == 0);
        CHECK(f1->type == teams::flow_tracker::flow_type::tcp);
        CHECK(t.count_teams_flows_detected() == 1);
        CHECK(t.count_total_pkts_processed() == 1);
        CHECK(t.count_teams_pkts_detected() == 1);

        auto f2 = t.track(teams_udp_srv_flow, {2, 0}, 100);
        CHECK(f2);
        CHECK(f2->id == 1);
        CHECK(f2->type == teams::flow_tracker::flow_type::udp_srv);
        CHECK(t.count_teams_flows_detected() == 2);
        CHECK(t.count_total_pkts_processed() == 2);
        CHECK(t.count_teams_pkts_detected() == 2);

        auto f11 = t.track(teams_tcp_flow, {2, 0}, 100);
        CHECK(f11);
        CHECK(f11->id == 0);
        CHECK(f11->type == teams::flow_tracker::flow_type::tcp);
        CHECK(t.count_teams_flows_detected() == 2);
        CHECK(t.count_total_pkts_processed() == 3);
        CHECK(t.count_teams_pkts_detected() == 3);

        auto f21 = t.track(teams_udp_srv_flow, {3, 0}, 100);
        CHECK(f21);
        CHECK(f21->id == 1);
        CHECK(f21->type == teams::flow_tracker::flow_type::udp_srv);
        CHECK(t.count_teams_flows_detected() == 2);
        CHECK(t.count_total_pkts_processed() == 4);
        CHECK(t.count_teams_pkts_detected() == 4);
    }

    SECTION("tracks teams p2p flows after stun") {

        net::ipv4_5tuple teams_stun_flow {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("209.9.215.34"),
                12433, 3478, 17
        };

        net::ipv4_5tuple teams_stun_flow2 {
                net::ipv4::str_to_addr("10.0.0.8"), net::ipv4::str_to_addr("209.9.215.34"),
                49922, 3478, 17
        };

        net::ipv4_5tuple non_teams_stun_flow {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("42.2.3.2"),
                12434, 3478, 17
        };

        net::ipv4_5tuple teams_p2p_flow {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("10.0.0.7"),
                12433, 40200, 17
        };

        net::ipv4_5tuple p2p_flow_with_previous_ip_port {
                net::ipv4::str_to_addr("10.0.0.8"), net::ipv4::str_to_addr("10.0.0.7"),
                49922, 40200, 17
        };

        net::ipv4_5tuple non_teams_flow_with_stun_port {
                net::ipv4::str_to_addr("10.0.0.2"), net::ipv4::str_to_addr("10.0.0.7"),
                12433, 53, 17
        };

        net::ipv4_5tuple non_teams_flow_with_stun_ip {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("10.0.0.7"),
                32555, 53, 17
        };

        net::ipv4_5tuple non_teams_tcp_flow_with_stun_ip_port {
                net::ipv4::str_to_addr("10.0.0.6"), net::ipv4::str_to_addr("39.20.20.22"),
                12433, 80, 6
        };

        const unsigned STUN_EXPIRATION = 10;
        teams::flow_tracker t(STUN_EXPIRATION);

        auto f11 = t.track(teams_stun_flow, {1, 0}, 100);
        CHECK(f11);
        CHECK(f11->id == 0);
        CHECK(f11->type == teams::flow_tracker::flow_type::udp_stun);
        CHECK(t.count_teams_flows_detected() == 1);
        CHECK(t.count_total_pkts_processed() == 1);
        CHECK(t.count_teams_pkts_detected() == 1);

        auto f12 = t.track(teams_stun_flow, {2, 0}, 100);
        CHECK(f12);
        CHECK(f12->id == 0);
        CHECK(f12->type == teams::flow_tracker::flow_type::udp_stun);
        CHECK(t.count_teams_flows_detected() == 1);
        CHECK(t.count_total_pkts_processed() == 2);
        CHECK(t.count_teams_pkts_detected() == 2);

        auto f21 = t.track(teams_p2p_flow, {2 + STUN_EXPIRATION - 1, 0}, 100);
        CHECK(f21);
        CHECK(f21->id == 1);
        CHECK(f21->type == teams::flow_tracker::flow_type::udp_p2p);
        CHECK(t.count_teams_flows_detected() == 2);
        CHECK(t.count_total_pkts_processed() == 3);
        CHECK(t.count_teams_pkts_detected() == 3);

        SECTION("does not track p2p flows after stun expiration") {

            INFO(t.count_teams_flows_detected());

            auto f31 = t.track(teams_stun_flow2, {1, 0}, 100);
            CHECK(f31);
            CHECK(f31->id == 2);
            CHECK(f31->type == teams::flow_tracker::flow_type::udp_stun);

            CHECK_FALSE(t.track(p2p_flow_with_previous_ip_port, {1 + STUN_EXPIRATION + 1, 0}, 100));
        }

        SECTION("does not track flows with only port or ip from previous stun") {
            CHECK_FALSE(t.track(non_teams_flow_with_stun_port, {5, 0}, 100));
            CHECK_FALSE(t.track(non_teams_flow_with_stun_ip, {5, 0}, 100));
        }

        SECTION("does not track non-UDP flows with previous STUN packet to ip+port seen") {
            CHECK_FALSE(t.track(non_teams_tcp_flow_with_stun_ip_port, {5, 0}, 100));
        }

        SECTION("does not track non-teams STUN flows") {
            CHECK_FALSE(t.track(non_teams_stun_flow, {5, 0}, 100));
        }
    }
}

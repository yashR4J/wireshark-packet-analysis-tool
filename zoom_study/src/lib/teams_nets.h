
#ifndef ZOOM_ANALYSIS_ZOOM_NETS_H
#define ZOOM_ANALYSIS_ZOOM_NETS_H

#ifndef TEAMS_ANALYSIS_TEAMS_NETS_H
#define TEAMS_ANALYSIS_TEAMS_NETS_H

#include "net.h"

#include <algorithm>
#include <vector>

namespace teams {

    class nets {

    public:

        static bool match(const uint32_t ip) {

            if (std::any_of(NETS.begin(), NETS.end(), [&ip](const auto& ip_mask) {
                return ip_mask.match(ip);
            })) return true;

            return false;
        }

        // addresses taken from:
        // https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide#skype-for-business-online-and-microsoft-teams

        // last update to list: Jul. 1, 2024

        static inline const std::vector<net::ipv4_mask> NETS = {
                { net::ipv4::str_to_addr("13.107.64.0"), ~(~uint32_t(0) >> 18) },
                { net::ipv4::str_to_addr("52.112.0.0"), ~(~uint32_t(0) >> 14) },
                { net::ipv4::str_to_addr("52.122.0.0"), ~(~uint32_t(0) >> 15) },
                { net::ipv4::str_to_addr("52.238.119.141"), ~(~uint32_t(0) >> 32) },
                { net::ipv4::str_to_addr("52.244.160.207"), ~(~uint32_t(0) >> 32) },
                { net::ipv4::str_to_addr("2603:1027::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2603:1037::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2603:1047::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2603:1057::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2603:1063::"), ~(~uint32_t(0) >> 38) },
                { net::ipv4::str_to_addr("2620:1ec:6::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2620:1ec:38::"), ~(~uint32_t(0) >> 48) },
                { net::ipv4::str_to_addr("2620:1ec:40::"), ~(~uint32_t(0) >> 42) }
        };
    };
}

#endif

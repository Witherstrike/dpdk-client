#include <map>
#include <cstddef>
#include <string>
#include <list>
#include "driver.h"

struct __attribute__((packed)) ping_payload_h {
    uint16_t     task_ID;
    uint32_t     task_start_tstamp;
    uint16_t     circ_times;
    uint32_t     next_hop_bit;
    uint8_t      hop_times;
    uint32_t     last_hop_delay;
    uint32_t     last_hop_link;
};

struct __attribute__((packed)) pong_payload_h {
    uint16_t     task_ID;
    uint32_t     task_start_tstamp;
    uint16_t     path_count;
    uint32_t     max_delay;
    uint32_t     max_delay_link;
    uint32_t     drop_link;
};

void send(dpdk_driver &driver);
void recv(dpdk_driver &driver);

int main(int argc, char *argv[]) {
    dpdk_driver driver;
    driver.init(argc, argv);
    while (true) {

    }
}

template <typename task_id_t>
class task_manager {
private: 
    std::map<std::string, std::list<task_id_t>> available_task_ids;
    std::map<task_id_t, std::string> used_id_type;
public:
    task_manager() {}

    void register_task_type(std::string type_name, task_id_t start, size_t max_jobs) {
        std::list<task_id_t> type_available_task_ids;
        for (task_id_t i = start; i < start + max_jobs; i++)
            type_available_task_ids.push_back(i);
        available_task_ids.emplace(type_name, std::move(type_available_task_ids));
    }

    std::map<std::string, std::list<task_id_t>> schedule() {
        return std::map<std::string, std::list<task_id_t>>(available_task_ids);
    }

    void release_id(task_id_t task_id) {
        auto it = used_id_type.find(task_id);
        if (it == used_id_type.end())
            return;
        std::string type = it->second;
        available_task_ids.at(type).push_back(task_id);
    }
};

void send(dpdk_driver &driver) {

}

void recv(dpdk_driver &driver) {

}

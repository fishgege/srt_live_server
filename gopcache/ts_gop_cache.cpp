#include "ts_gop_cache.h"
#include "logging/logger.h"
#include <assert.h>

namespace srt_media {

#define TS_PACKET_HEADER_SIZE 4

ts_gop_cache::ts_gop_cache() {
    memset(_pat_p, 0, MPEG_TS_SIZE);
    memset(_pmt_p, 0, MPEG_TS_SIZE);
}

ts_gop_cache::~ts_gop_cache() {
    std::unordered_map<std::string, std::list<std::shared_ptr<Media_Packet>>> _packet_map;

    for (auto iter = _packet_map.begin(); iter != _packet_map.end(); iter++) {
        auto packet_list = iter->second;
        packet_list.clear();
    }
}

void ts_gop_cache::save_gop_cache(char* data_p, int data_len, std::string streamid) {
    if ((data_p == nullptr) || (data_p[0] != 0x47) || (data_len == 0)) {
        assert(0);
        return;
    }

    if ((data_len % MPEG_TS_SIZE) != 0) {
        assert(0);
        return;
    }
    
    for (int index = 0; index < (data_len / MPEG_TS_SIZE); index++) {
        char* ts_data_p = data_p + index * MPEG_TS_SIZE;
        
        if (ts_data_p[0] != 0x47) {
            assert(0);
            return;
        }

        ts_packet_header_t ts_header_info;
        memset(&ts_header_info, 0, sizeof(ts_packet_header_t));
        ts_header_info.sync_byte = ts_data_p[0];
	    ts_header_info.transport_error_indicator = (ts_data_p[1] >> 7) & 0x01;
	    ts_header_info.payload_unit_start_indicator = (ts_data_p[1] >> 6) & 0x01;
	    ts_header_info.transport_priority = (ts_data_p[1] >> 5) & 0x01;
	    ts_header_info.transport_scrambling_control = (ts_data_p[3] >> 6) & 0x03;
	    ts_header_info.adaptation_field_control = (ts_data_p[3] >> 4) & 0x03;
	    ts_header_info.continuity_counter = ts_data_p[3] & 0x0F;
        
        //pid:xxxo oooo oooo oooo
        ts_header_info.PID = ((int(ts_data_p[1] & 0x1f)) << 8) | ts_data_p[2];

        InfoLogf("sync_byte=0x%02x, transport_error_indicator=%d, payload_unit_start_indicator=%d, \
transport_priority=%d, transport_scrambling_control=%d, adaptation_field_control=%d, continuity_counter=%d, PID=%d", 
            ts_header_info.sync_byte,
            ts_header_info.transport_error_indicator,
            ts_header_info.payload_unit_start_indicator,
            ts_header_info.transport_priority,
            ts_header_info.transport_scrambling_control,
            ts_header_info.adaptation_field_control,
            ts_header_info.continuity_counter,
            ts_header_info.PID);
        int offset = 4;

        if (TS_PID_SDT == ts_header_info.PID) {
            return;
        }
        if (ts_header_info.adaptation_field_control & 0x02) {
            unsigned char adaptation_length = ts_data_p[offset++];
            InfoLogf("adaption length=%d", adaptation_length);
            offset += adaptation_length;
        }

        bool is_pmt = false;

        if (ts_header_info.adaptation_field_control & 0x01) {
            if (ts_header_info.PID == TS_PID_PAT) {
                clear_media_packet(streamid);
            }
            if ((ts_header_info.PID == TS_PID_PAT) && (_pat_p[0] == 0)) {
                InfoLog("ts packet is PAT...");
                if (ts_header_info.payload_unit_start_indicator) {
                    offset += 1;
                }
                get_pat_info(ts_data_p + offset, MPEG_TS_SIZE - offset, _pat_info);
                memcpy(_pat_p, ts_data_p, sizeof(_pat_p));
            }

            for (int index = 0; index < int(_pat_info.pmt_info_vec.size()); index++) {
                auto pmt_info = _pat_info.pmt_info_vec[index];
                if (ts_header_info.PID == pmt_info.pmt_pid) {
                    if (ts_header_info.payload_unit_start_indicator) {
                        offset += 1;
                    }
                    is_pmt = true;
                    if (_pmt_p[0] == 0x47) {
                        break;
                    }
                    InfoLogf("ts packet is PMT, PMT_PID=%d", pmt_info.pmt_pid);
                    memcpy(_pmt_p, ts_data_p, sizeof(_pmt_p));
                    get_pmt_info(ts_data_p + offset, MPEG_TS_SIZE - offset, _pmt_info);
                }
            }

            if ((ts_header_info.PID != TS_PID_PAT) && !is_pmt && (ts_header_info.continuity_counter == 0)) {
                ts_pes_header pes_header_info;
                InfoLogf("pes offset=%d", offset);
                pes_is_iframe(ts_data_p + offset, MPEG_TS_SIZE - offset, pes_header_info);
            }
        }
        insert_media_packet(streamid, ts_data_p, MPEG_TS_SIZE);
    }
    return;
}

bool ts_gop_cache::pes_is_iframe(char* data_p, int data_len, ts_pes_header& pes_header_info) {
    pes_header_info.packet_start_code_prefix = int(data_p[0]) << 16 | int(data_p[1]) << 8 | data_p[2];
    pes_header_info.stream_id = data_p[3];
    pes_header_info.PES_packet_length = int(data_p[4]) << 8 | data_p[5];

    if (pes_header_info.packet_start_code_prefix != 0x000001) {
        InfoLogBody("error media offset:", (unsigned char*)data_p, 64);
        return false;
    }
    //....data_p[6]
    //....data_p[7]
    pes_header_info.PES_header_data_length = (unsigned char)data_p[8];

    InfoLogf("start_code=0x%06x", pes_header_info.packet_start_code_prefix);
    InfoLogf("media length:%d", pes_header_info.PES_header_data_length);
    InfoLogBody("media_header:", (unsigned char*)data_p+pes_header_info.PES_header_data_length+9, 64);
    return false;
}

int ts_gop_cache::send_gop_cache(std::string streamid, SRTSOCKET dst_srtsocket) {
    int gop_total = 0;

    auto iter = _packet_map.find(streamid);

    if (iter == _packet_map.end()) {
        ErrorLogf("send_gop_cache fail to find streamid(%s)", streamid.c_str());
        return 0;
    }

    std::list<std::shared_ptr<Media_Packet>> packet_list = iter->second;

    for (auto packet_iter = packet_list.begin(); packet_iter != packet_list.end(); packet_iter++) {
        gop_total += (*packet_iter)->get_size();
        srt_send(dst_srtsocket, (*packet_iter)->get_data(), (*packet_iter)->get_size());
    }
    InfoLogf("send_gop_cache send steamid=%s, total=%d", streamid.c_str(), gop_total);
    return gop_total;
}

int ts_gop_cache::get_pat_info(char* data_p, int data_len, ts_pat_info_t& pat_info) {
    pat_info.pat_head_info.table_id = data_p[0];
    pat_info.pat_head_info.section_syntax_indicator = data_p[1] &0x80;
    pat_info.pat_head_info.zero_bit = data_p[1] &0x40;
    pat_info.pat_head_info.reserved1 = data_p[1] &0x30;
    pat_info.pat_head_info.section_length = ((int)(data_p[1]&0x0f) << 8) | data_p[2];
    pat_info.pat_head_info.transport_stream_id = ((int)(data_p[3]) << 8) | data_p[4];
    pat_info.pat_head_info.reserved2 = data_p[5] &0xc0;
    pat_info.pat_head_info.version_number = (data_p[5] & 0x3e) >> 1;
    pat_info.pat_head_info.current_next_indicator = data_p[5] & 0x01;
    pat_info.pat_head_info.section_number = data_p[6];
    pat_info.pat_head_info.last_section_number = data_p[7];

    int offset = 8;
    InfoLogf("pat section_length=%d", pat_info.pat_head_info.section_length);
    for (int index = offset; index < pat_info.pat_head_info.section_length + offset - 5 - 4; index += 4) {
        ts_pmt_in_pat_item_t item_info;
        memset(&item_info, 0, sizeof(ts_pmt_in_pat_item_t));
        item_info.program_number = (int(data_p[index]) << 8) | data_p[index+1];
        if (item_info.program_number != 0) {
            item_info.pmt_pid = (int(data_p[index+2] & 0x1f) << 8) | data_p[index+3];
            InfoLogf("program_number=%d, pmt_pid=%d", item_info.program_number, item_info.pmt_pid);
        }
        pat_info.pmt_info_vec.push_back(item_info);
    }
    return 0;
}

int ts_gop_cache::get_pmt_info(char* data_p, int data_len, ts_pmt_info_t& pmt_info) {
    pmt_info.pmt_head_info.table_id = data_p[0];
    pmt_info.pmt_head_info.section_syntax_indicator = (data_p[1] & 0x80) >> 7;
    pmt_info.pmt_head_info.section_length = ((int(data_p[1] & 0x0f)) << 8) | data_p[2];
    pmt_info.pmt_head_info.program_number = (int(data_p[3]) << 8) | data_p[4];
    pmt_info.pmt_head_info.version_number = (data_p[5] & 0x3e) >> 1;
    pmt_info.pmt_head_info.current_next_indicator = data_p[5] & 0x01;
    pmt_info.pmt_head_info.section_number = data_p[6];
    pmt_info.pmt_head_info.last_section_number = data_p[7];
    pmt_info.pmt_head_info.PCR_PID = (int(data_p[8] & 0x1f) << 8) | data_p[9];
    pmt_info.pmt_head_info.program_info_length = (int(data_p[10] & 0x0f) << 8) | data_p[11];

    InfoLogf("pmt section_length=%d, program_info_length=%d",
        pmt_info.pmt_head_info.section_length, pmt_info.pmt_head_info.program_info_length);

    int offset = 12;
    for (int index = 0; index < pmt_info.pmt_head_info.program_info_length; index++) {
        pmt_info.program_info.push_back(data_p[offset++]);
    }
    if (pmt_info.pmt_head_info.program_info_length > 0) {
        InfoLogf("pmt program_info_length=%d, info:%s", 
            pmt_info.pmt_head_info.program_info_length, pmt_info.program_info.c_str());
    }

    int ES_info_length = 0;

    for (int index = offset; index < pmt_info.pmt_head_info.section_length + 3 - 4; index += 5 + ES_info_length) {
        ts_pid_in_pmt_item_t item_info;
        item_info.stream_type = data_p[index];
        item_info.elementary_PID = (int(data_p[index+1] & 0x1f) << 8) | data_p[index+2];
        item_info.ES_info_length = ES_info_length = (int(data_p[index+3] & 0x0f) << 8) | data_p[index+4];

        int info_offset = index + 5;
        for (int info_index = 0; info_index < ES_info_length; info_index++) {
            item_info.ES_info.push_back(data_p[info_offset+info_offset]);
        }
        InfoLogf("pid=%d, steam_type=%d, es_info_len=%d", 
            item_info.elementary_PID, item_info.stream_type, item_info.ES_info_length);
    }
    return 0;
}

void ts_gop_cache::clear_media_packet(std::string streamid) {
    auto iter = _packet_map.find(streamid);

    if (iter == _packet_map.end()) {
        return;
    }

    iter->second.clear();

    
    return;
}

void ts_gop_cache::insert_media_packet(std::string streamid, char* data_p, int data_len) {
    auto iter = _packet_map.find(streamid);
    std::shared_ptr<Media_Packet> packet_ptr = std::make_shared<Media_Packet>(data_p, data_len);

    if (iter != _packet_map.end()) {
        iter->second.push_back(packet_ptr);
        return;
    }
    std::list<std::shared_ptr<Media_Packet>> packet_list;
    packet_list.push_back(packet_ptr);

    _packet_map.insert(std::make_pair(streamid, packet_list));
    return;
}

}
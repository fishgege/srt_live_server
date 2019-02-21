#include "srt_handle.h"
#include "logging/logger.h"
#include "include/srt/udt.h"
#include <stdio.h>
#include <vector>
#include <sstream>
#include <iomanip>

namespace srt_media {

#define QUEUE_MAX_SIZE 10

const unsigned long MONITOR_TIMEOUT = 5000;
bool MONITOR_STATICS_ENABLE = true;

srt_handle::srt_handle():_last_timestamp(0) {

}

srt_handle::~srt_handle() {

}

int srt_handle::start() {
    _handle_pollid = srt_epoll_create();
    if (_handle_pollid < -1) {
        ErrorLogf("srt handle srt_epoll_create error, _handle_pollid=%d", _handle_pollid);
        return -1;
    }

    _work_thread_ptr = std::make_shared<std::thread>(std::bind(&srt_handle::onwork, this));
    
    
    return 0;
}

void srt_handle::stop() {
    _work_thread_ptr->join();
    return;
}

int srt_handle::send_media_data(std::string stream_id, char* data_p, int data_size) {
    int list_size = 0;

    auto iter = _streamid_map.find(stream_id);
    if (iter == _streamid_map.end()) {
        return list_size;
    } else {
        if (iter->second.empty()) {
            return list_size;
        }
        list_size = iter->second.size();
        //InfoLogf("send_media_data streamid=%s, datasize=%d, client size=%lu", 
        //    stream_id.c_str(), data_size, iter->second.size());
        std::vector<SRTSOCKET> remove_list;
        for (auto map_iter = iter->second.begin(); map_iter != iter->second.end(); map_iter++) {
            if (map_iter->second == 0) {
                _gop_cache_obj.send_gop_cache(stream_id, (SRTSOCKET)(map_iter->first));
                map_iter->second = 1;
            }
            int ret = srt_send((SRTSOCKET)(map_iter->first), data_p, data_size);
            if (ret == SRT_ERROR) {
                remove_list.push_back((SRTSOCKET)(map_iter->first));
            }
            debug_statics(map_iter->first, stream_id);
        }

        for (int index = 0; index < remove_list.size(); index++) {
            remove_srtsocket((SRTSOCKET)remove_list[index], stream_id);
        }
    }
    return list_size;
}

void srt_handle::debug_statics(SRTSOCKET srtsocket, const std::string& streamid) {
    SRT_TRACEBSTATS mon;
    srt_bstats(srtsocket, &mon, 1);
    std::ostringstream output;
    unsigned long now_ul = now_ms();

    if (!MONITOR_STATICS_ENABLE) {
        return;
    }
    if (_last_timestamp == 0) {
        _last_timestamp = now_ul;
        return;
    }

    if ((now_ul - _last_timestamp) < MONITOR_TIMEOUT) {
        return;
    }
    _last_timestamp = now_ul;
    output << "======= SRT STATS: sid=" << streamid << std::endl;
    output << "PACKETS     SENT: " << std::setw(11) << mon.pktSent            << "  RECEIVED:   " << std::setw(11) << mon.pktRecv              << std::endl;
    output << "LOST PKT    SENT: " << std::setw(11) << mon.pktSndLoss         << "  RECEIVED:   " << std::setw(11) << mon.pktRcvLoss           << std::endl;
    output << "REXMIT      SENT: " << std::setw(11) << mon.pktRetrans         << "  RECEIVED:   " << std::setw(11) << mon.pktRcvRetrans        << std::endl;
    output << "DROP PKT    SENT: " << std::setw(11) << mon.pktSndDrop         << "  RECEIVED:   " << std::setw(11) << mon.pktRcvDrop           << std::endl;
    output << "RATE     SENDING: " << std::setw(11) << mon.mbpsSendRate       << "  RECEIVING:  " << std::setw(11) << mon.mbpsRecvRate         << std::endl;
    output << "BELATED RECEIVED: " << std::setw(11) << mon.pktRcvBelated      << "  AVG TIME:   " << std::setw(11) << mon.pktRcvAvgBelatedTime << std::endl;
    output << "REORDER DISTANCE: " << std::setw(11) << mon.pktReorderDistance << std::endl;
    output << "WINDOW      FLOW: " << std::setw(11) << mon.pktFlowWindow      << "  CONGESTION: " << std::setw(11) << mon.pktCongestionWindow  << "  FLIGHT: " << std::setw(11) << mon.pktFlightSize << std::endl;
    output << "LINK         RTT: " << std::setw(9)  << mon.msRTT            << "ms  BANDWIDTH:  " << std::setw(7)  << mon.mbpsBandwidth    << "Mb/s " << std::endl;
    output << "BUFFERLEFT:  SND: " << std::setw(11) << mon.byteAvailSndBuf    << "  RCV:        " << std::setw(11) << mon.byteAvailRcvBuf      << std::endl;

    InfoLogf("\r\n%s", output.str().c_str());
    return;
}

void srt_handle::add_srtsocket(SRTSOCKET write_srtsocket, std::string stream_id) {
    auto iter = _streamid_map.find(stream_id);
    if (iter == _streamid_map.end()) {
        std::unordered_map<SRTSOCKET, int> srtsocket_map;
        srtsocket_map.insert(std::pair<SRTSOCKET, int>(write_srtsocket, 0));

        _streamid_map.insert(std::pair<std::string, std::unordered_map<SRTSOCKET, int>>(stream_id, srtsocket_map));
    } else {
        iter->second.insert(std::pair<SRTSOCKET, int>(write_srtsocket, 0));
    }

    return;
}

void srt_handle::onwork() {
    int rcv_total = 0;
    const int READ_LEN = 188*7;
    _file_offset = 0;

    while(true) {
        if (_conn_map.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        SRTSOCKET read_fds = -1;
        SRTSOCKET write_fds = -1;
        int rfd_num = 1;
        int wfd_num = 1;
        int ret = srt_epoll_wait(_handle_pollid, &read_fds, &rfd_num, &write_fds, &wfd_num, -1,
                        nullptr, nullptr, nullptr, nullptr);
        if (ret < 0) {
            InfoLogf("epoll is timeout, ret=%d", ret);
            continue;
        }

        SRT_SOCKSTATUS status = SRTS_INIT;
        std::string streamid;

        if (rfd_num > 0) {
            status = srt_getsockstate(read_fds);
            streamid = UDT::getstreamid(read_fds);
        } else if (wfd_num > 0) {
            status = srt_getsockstate(write_fds);
            streamid = UDT::getstreamid(write_fds);
        }
        //InfoLogf("epoll get: ret=%d, rfd_num=%d, wfd_num=%d, writefds=%d, readfds=%d, status=%d, streamid=%s", 
        //    ret, rfd_num, wfd_num, write_fds, read_fds, status, streamid.c_str());
        switch(status) {
            case SRTS_CONNECTED:
            {
                int mode = 0;
                SRTSOCKET rcv_srt_socket = -1;
                SRTSOCKET snd_srt_socket = -1;

                if (rfd_num > 0) {
                    mode = get_srt_mode(read_fds);
                    rcv_srt_socket = read_fds;
                    if (mode == PUSH_SRT_MODE) {
                        //InfoLogf("work_mode recv work mode:work_srt_socket=%d, streamid=%s", 
                        //    rcv_srt_socket, streamid.c_str());
                        char read_data_p[READ_LEN];
                        int ret = 0;
    
                        ret = srt_recv(rcv_srt_socket, read_data_p, READ_LEN);
                        if (ret <= 0) {
                            continue;
                        }
    
                        _gop_cache_obj.save_gop_cache(read_data_p, READ_LEN, streamid);
                        rcv_total += ret;
                        send_media_data(streamid, read_data_p, ret);
    
                        //InfoLogf("srt_recv return %d, rcv_total=%d", ret, rcv_total);
                    }
                    if (mode == PULL_SRT_MODE) {
                        //InfoLogf("work_mode send work mode:work_srt_socket=%d, streamid=%s", 
                        //    rcv_srt_socket, streamid.c_str());
                        add_srtsocket(rcv_srt_socket, streamid);
                    }
                }
                if (wfd_num > 0) {
                    mode = get_srt_mode(write_fds);
                    snd_srt_socket = write_fds;

                    if (mode == PUSH_SRT_MODE) {
                        //InfoLogf("work_mode recv work mode:work_srt_socket=%d, streamid=%s", 
                        //    snd_srt_socket, streamid.c_str());
                        char read_data_p[READ_LEN];
                        int ret = 0;
    
                        ret = srt_recv(snd_srt_socket, read_data_p, READ_LEN);
                        if (ret <= 0) {
                            continue;
                        }
                        
                        _gop_cache_obj.save_gop_cache(read_data_p, READ_LEN, streamid);
                        rcv_total += ret;
                        send_media_data(streamid, read_data_p, ret);
    
                        //InfoLogf("srt_recv return %d, rcv_total=%d", ret, rcv_total);
                    }
                    if (mode == PULL_SRT_MODE) {
                        InfoLogf("work_mode send work mode:work_srt_socket=%d, streamid=%s", snd_srt_socket, streamid.c_str());
    
                        add_srtsocket(snd_srt_socket, streamid);
                        int conn_event = SRT_EPOLL_IN | SRT_EPOLL_ERR;
                        srt_epoll_update_usock(_handle_pollid, snd_srt_socket, &conn_event);
                    }
                }
                
                break;
            }
            case SRTS_BROKEN:
            {
                remove_srtsocket(read_fds, streamid);
                break;
            }
            default:
                ErrorLogf("srt handle unkown status=%d", status);
                break;
        }
    }
}

void srt_handle::remove_srtsocket(SRTSOCKET srtsocket, std::string stream_id) {
    WarnLogf("socket broken: read_fd=%d, streamid=%s", srtsocket, stream_id.c_str());
    srt_epoll_remove_usock(_handle_pollid, srtsocket);
    srt_close(srtsocket);

    auto iter = _streamid_map.find(stream_id);
    if (iter != _streamid_map.end()) {
        auto srtsocket_map = iter->second;
        if (srtsocket_map.size() == 0) {
            _streamid_map.erase(stream_id);
        } else if (srtsocket_map.size() == 1) {
            srtsocket_map.erase(srtsocket);
            _streamid_map.erase(stream_id);
        } else {
            srtsocket_map.erase(srtsocket);
        }
    }

    {
        std::lock_guard<std::mutex> lockf(_conn_mutex);
        _conn_map.erase(srtsocket);
    }
    
    return;
}

int srt_handle::read_tsfile(char* data_p, int data_len) {
    const char* TS_FILENAME = "1.ts";
    int read_len = 0;
    FILE* file_p = fopen(TS_FILENAME, "rb");
    if (file_p) {
        fseek(file_p, _file_offset, SEEK_SET);
        read_len = fread(data_p, 1, data_len, file_p);
        if (read_len > 0) {
            _file_offset += read_len;
        }
        fclose(file_p);
    }
    return read_len;
}

void srt_handle::add_newconn(std::shared_ptr<srt_conn> conn_ptr, int events) {
    InfoLogf("new conn added: %d", conn_ptr->get_conn());

    int val_i;
    int opt_len = sizeof(int);

    val_i = 1000;
    srt_setsockopt(conn_ptr->get_conn(), 0, SRTO_LATENCY, &val_i, opt_len);
    val_i = 2048;
    srt_setsockopt(conn_ptr->get_conn(), 0, SRTO_MAXBW, &val_i, opt_len);

    srt_getsockopt(conn_ptr->get_conn(), 0, SRTO_LATENCY, &val_i, &opt_len);
    InfoLogf("srto SRTO_LATENCY=%d", val_i);
    srt_getsockopt(conn_ptr->get_conn(), 0, SRTO_SNDBUF, &val_i, &opt_len);
    InfoLogf("srto SRTO_SNDBUF=%d", val_i);
    srt_getsockopt(conn_ptr->get_conn(), 0, SRTO_RCVBUF, &val_i, &opt_len);
    InfoLogf("srto SRTO_RCVBUF=%d", val_i);
    srt_getsockopt(conn_ptr->get_conn(), 0, SRTO_MAXBW, &val_i, &opt_len);
    InfoLogf("srto SRTO_MAXBW=%d", val_i);

    int ret = srt_epoll_add_usock(_handle_pollid, conn_ptr->get_conn(), &events);
    if (ret < 0) {
        ErrorLogf("srt server run add epoll error:%d", ret);
        return;
    }
    auto pair_item = std::make_pair<SRTSOCKET, std::shared_ptr<srt_conn>>(conn_ptr->get_conn(), std::move(conn_ptr));
    {
        std::lock_guard<std::mutex> lockf(_conn_mutex);
        _conn_map.insert(pair_item);
    }
    
    return;
}

int srt_handle::get_srt_mode(SRTSOCKET conn_srt_socket) {
    std::lock_guard<std::mutex> lockf(_conn_mutex);
    auto iter = _conn_map.find(conn_srt_socket);
    if (iter == _conn_map.end()) {
        return 0;
    }
    return iter->second->get_mode();
}
}
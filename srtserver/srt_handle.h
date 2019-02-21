#ifndef SRT_HANDLE_H
#define SRT_HANDLE_H
#include "srt/srt.h"
#include "srt_conn.h"
#include "gopcache/ts_gop_cache.h"
#include "sys/timehelp.h"

#include <thread>
#include <memory>
#include <unordered_map>
#include <list>
#include <string.h>
#include <mutex>

namespace srt_media {

class srt_handle {
public:
    srt_handle();
    ~srt_handle();

    int start();
    void stop();

    void add_newconn(std::shared_ptr<srt_conn> conn_ptr, int events);
    int get_srt_mode(SRTSOCKET conn_srt_socket);

private:
    void onwork();
    int read_tsfile(char* data_p, int data_len);

    int send_media_data(std::string stream_id, char* data_p, int data_size);
    void add_srtsocket(SRTSOCKET write_srtsocket, std::string stream_id);
    void remove_srtsocket(SRTSOCKET srtsocket, std::string stream_id);

    void debug_statics(SRTSOCKET srtsocket, const std::string& streamid);
private:
    int _handle_pollid;
    std::unordered_map<SRTSOCKET, std::shared_ptr<srt_conn>> _conn_map;
    std::shared_ptr<std::thread> _work_thread_ptr;
    int _file_offset;

    std::unordered_map<std::string, std::unordered_map<SRTSOCKET, int>> _streamid_map;//streamid, list<SRTSOCKET>
    ts_gop_cache _gop_cache_obj;
    std::mutex _conn_mutex;

    unsigned long _last_timestamp;
};
}

#endif //SRT_HANDLE_H
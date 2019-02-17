#include "ts_gop_cache.h"
#include "../logging/logger.h"
#include <string.h>
#include <stdio.h>

using namespace srt_media;

int main(int argn, char** argv) {
    if (argn != 2) {
        printf("input parameter error\r\n");
        return -1;
    }

    InitLog("../conf/log.properties");

    std::string ts_file_name(argv[1]);

    ts_gop_cache gop_cache_obj;
    int read_len = 0;

    FILE* file_handle_p = fopen(ts_file_name.c_str(), "rb");
    if (file_handle_p == nullptr) {
        ErrorLogf("open file(%s) error.", ts_file_name.c_str());
        return -1;
    }
    InfoLogf("open file(%s) ok.", ts_file_name.c_str());

    do {
        char data_p[MPEG_TS_SIZE];
        read_len = fread(data_p, 1, MPEG_TS_SIZE, file_handle_p);
        gop_cache_obj.save_gop_cache(data_p, MPEG_TS_SIZE, "streamid100");    
    } while(read_len == MPEG_TS_SIZE);

    fclose(file_handle_p);

    return 0;
}
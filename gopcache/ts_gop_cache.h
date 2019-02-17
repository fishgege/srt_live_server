#ifndef TS_GOP_CACHE_H
#define TS_GOP_CACHE_H
#include "mem/media_packet.h"
#include "srt/srt.h"
#include <list>
#include <unordered_map>
#include <string.h>
#include <vector>

namespace srt_media {
#define MPEG_TS_SIZE 188

enum ETS_PID
{
	TS_PID_PAT	= 0x00, // program association table
	TS_PID_CAT	= 0x01, // conditional access table
	TS_PID_TSDT	= 0x02, // transport stream description table
	TS_PID_IPMP	= 0x03, // IPMP control information table
	// 0x0004-0x000F Reserved
	// 0x0010-0x1FFE May be assigned as network_PID, Program_map_PID, elementary_PID, or for other purposes
    TS_PID_SDT  = 0x11, // https://en.wikipedia.org/wiki/Service_Description_Table / https://en.wikipedia.org/wiki/MPEG_transport_stream
	TS_PID_USER	= 0x0042,
	TS_PID_NULL	= 0x1FFF, // Null packet
};

// ISO/IEC 13818-1:2015 (E)
// 2.4.4.9 Semantic definition of fields in transport stream program map section
// Table 2-34 ¨C Stream type assignments(p69)
enum EPSI_STREAM_TYPE
{
	PSI_STREAM_RESERVED			= 0x00, // ITU-T | ISO/IEC Reserved
	PSI_STREAM_MPEG1			= 0x01, // ISO/IEC 11172-2 Video
	PSI_STREAM_MPEG2			= 0x02, // Rec. ITU-T H.262 | ISO/IEC 13818-2 Video or ISO/IEC 11172-2 constrained parameter video stream(see Note 2)
	PSI_STREAM_AUDIO_MPEG1		= 0x03, // ISO/IEC 11172-3 Audio
	PSI_STREAM_MP3				= 0x04, // ISO/IEC 13818-3 Audio
	PSI_STREAM_PRIVATE_SECTION	= 0x05, // Rec. ITU-T H.222.0 | ISO/IEC 13818-1 private_sections
	PSI_STREAM_PRIVATE_DATA		= 0x06, // Rec. ITU-T H.222.0 | ISO/IEC 13818-1 PES packets containing private data
	PSI_STREAM_MHEG				= 0x07, // ISO/IEC 13522 MHEG
	PSI_STREAM_DSMCC			= 0x08, // Rec. ITU-T H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC
	PSI_STREAM_H222_ATM			= 0x09, // Rec. ITU-T H.222.1
	PSI_STREAM_DSMCC_A			= 0x0a, // ISO/IEC 13818-6(Extensions for DSM-CC) type A
	PSI_STREAM_DSMCC_B			= 0x0b, // ISO/IEC 13818-6(Extensions for DSM-CC) type B
	PSI_STREAM_DSMCC_C			= 0x0c, // ISO/IEC 13818-6(Extensions for DSM-CC) type C
	PSI_STREAM_DSMCC_D			= 0x0d, // ISO/IEC 13818-6(Extensions for DSM-CC) type D
	PSI_STREAM_H222_Aux			= 0x0e, // Rec. ITU-T H.222.0 | ISO/IEC 13818-1 auxiliary
	PSI_STREAM_AAC				= 0x0f, // ISO/IEC 13818-7 Audio with ADTS transport syntax
	PSI_STREAM_MPEG4			= 0x10, // ISO/IEC 14496-2 Visual
	PSI_STREAM_MPEG4_AAC_LATM	= 0x11, // ISO/IEC 14496-3 Audio with the LATM transport syntax as defined in ISO/IEC 14496-3
	PSI_STREAM_MPEG4_PES		= 0x12, // ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in PES packets
	PSI_STREAM_MPEG4_SECTIONS	= 0x13, // ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in ISO/IEC 14496_sections
	PSI_STREAM_MPEG2_SDP		= 0x14, // ISO/IEC 13818-6 Synchronized Download Protocol
	PSI_STREAM_PES_META			= 0x15, // Metadata carried in PES packets
	PSI_STREAM_SECTION_META		= 0x16, // Metadata carried in metadata_sections
	PSI_STREAM_DSMCC_DATA		= 0x17, // Metadata carried in ISO/IEC 13818-6 Data Carousel
	PSI_STREAM_DSMCC_OBJECT		= 0x18, // Metadata carried in ISO/IEC 13818-6 Object Carousel
	PSI_STREAM_DSMCC_SDP		= 0x19, // Metadata carried in ISO/IEC 13818-6 Synchronized Download Protocol
	PSI_STREAM_MPEG2_IPMP		= 0x1a, // IPMP stream (defined in ISO/IEC 13818-11, MPEG-2 IPMP)
	PSI_STREAM_H264				= 0x1b, // H.264
	PSI_STREAM_MPEG4_AAC		= 0x1c, // ISO/IEC 14496-3 Audio, without using any additional transport syntax, such as DST, ALS and SLS
	PSI_STREAM_MPEG4_TEXT		= 0x1d, // ISO/IEC 14496-17 Text
	PSI_STREAM_AUX_VIDEO		= 0x1e, // Auxiliary video stream as defined in ISO/IEC 23002-3
	PSI_STREAM_H264_SVC			= 0x1f, // SVC video sub-bitstream of an AVC video stream conforming to one or more profiles defined in Annex G of Rec. ITU-T H.264 | ISO/IEC 14496-10
	PSI_STREAM_H264_MVC			= 0x20, // MVC video sub-bitstream of an AVC video stream conforming to one or more profiles defined in Annex H of Rec. ITU-T H.264 | ISO/IEC 14496-10
	PSI_STREAM_JPEG_2000		= 0x21, // Video stream conforming to one or more profiles as defined in Rec. ITU-T T.800 | ISO/IEC 15444-1
	PSI_STREAM_MPEG2_3D			= 0x22, // Additional view Rec. ITU-T H.262 | ISO/IEC 13818-2 video stream for service-compatible stereoscopic 3D services
	PSI_STREAM_MPEG4_3D			= 0x23, // Additional view Rec. ITU-T H.264 | ISO/IEC 14496-10 video stream conforming to one or more profiles defined in Annex A for service-compatible stereoscopic 3D services
	PSI_STREAM_H265				= 0x24, // Rec. ITU-T H.265 | ISO/IEC 23008-2 video stream or an HEVC temporal video sub-bitstream
	PSI_STREAM_H265_subset		= 0x25, // HEVC temporal video subset of an HEVC video stream conforming to one or more profiles defined in Annex A of Rec. ITU-T H.265 | ISO/IEC 23008-2
	PSI_STREAM_H264_MVCD		= 0x26, // MVCD video sub-bitstream of an AVC video stream conforming to one or more profiles defined in Annex I of Rec. ITU-T H.264 | ISO/IEC 14496-10
	// 0x27-0x7E Rec. ITU-T H.222.0 | ISO/IEC 13818-1 Reserved
	PSI_STREAM_IPMP				= 0x7F, // IPMP stream
	// 0x80-0xFF User Private
	PSI_STREAM_VIDEO_CAVS		= 0x42, // ffmpeg/libavformat/mpegts.h
	PSI_STREAM_AUDIO_AC3		= 0x81, // ffmpeg/libavformat/mpegts.h
	PSI_STREAM_AUDIO_DTS		= 0x8a, // ffmpeg/libavformat/mpegts.h
	PSI_STREAM_VIDEO_DIRAC		= 0xd1, // ffmpeg/libavformat/mpegts.h
	PSI_STREAM_VIDEO_VC1		= 0xea, // ffmpeg/libavformat/mpegts.h
	PSI_STREAM_VIDEO_SVAC		= 0x80, // GBT 25724-2010 SVAC(2014)
	PSI_STREAM_AUDIO_SVAC		= 0x9B, // GBT 25724-2010 SVAC(2014)
	PSI_STREAM_AUDIO_G711		= 0x90,
	PSI_STREAM_AUDIO_G722		= 0x92,
	PSI_STREAM_AUDIO_G723		= 0x93,
	PSI_STREAM_AUDIO_G729		= 0x99,
};

struct ts_packet_header_t
{
    unsigned char sync_byte;
	unsigned short transport_error_indicator : 1;
	unsigned short payload_unit_start_indicator : 1;
	unsigned short transport_priority : 1;
    unsigned short PID:13;
	unsigned int transport_scrambling_control : 2;
	unsigned int adaptation_field_control : 2;
	unsigned int continuity_counter : 4;
};

struct ts_pmt_in_pat_item_t {
    unsigned short program_number;
    unsigned short reserved : 3;
    unsigned short pmt_pid : 13;
};

struct ts_pat_head_t {
    unsigned char table_id;
    unsigned short section_syntax_indicator : 1;
    unsigned short zero_bit : 1;
    unsigned short reserved1 : 2;
    unsigned short section_length : 12;
    unsigned short transport_stream_id;
    unsigned char reserved2 : 2;
    unsigned char version_number : 5;
    unsigned char current_next_indicator : 1;
    unsigned char section_number;
    unsigned char last_section_number;
};

struct ts_pat_info_t {
    ts_pat_head_t pat_head_info;
    std::vector<ts_pmt_in_pat_item_t> pmt_info_vec;
};

struct ts_pid_in_pmt_item_t {
    unsigned char stream_type;
    unsigned short reserved1 : 3;
    unsigned short elementary_PID : 13;
    unsigned short reserved2 : 4;
    unsigned short ES_info_length : 12;
    std::string ES_info;
};

struct ts_pmt_head_t {
    unsigned char table_id;
    unsigned short section_syntax_indicator : 1;
    unsigned short zero_bit : 1;
    unsigned short reserved1 : 2;
    unsigned short section_length : 12;
    unsigned short program_number;
    unsigned char reserved2 : 2;
    unsigned char version_number : 5;
    unsigned char current_next_indicator : 1;
    unsigned char section_number;
    unsigned char last_section_number;
    unsigned short reserved3 : 3;
    unsigned short PCR_PID : 13;
    unsigned short reserved4 : 4;
    unsigned short program_info_length : 12;
};

struct ts_pmt_info_t {
    ts_pmt_head_t pmt_head_info;
    std::vector<ts_pid_in_pmt_item_t> pid_info_vec;
    std::string program_info;
};

struct ts_pes_header {
	unsigned int packet_start_code_prefix : 24;
    unsigned int stream_id : 8;
    unsigned short PES_packet_length;
	unsigned char fix_10 : 2;
    unsigned char PES_scrambling_control : 2;
	unsigned char PES_priority :1 ;
	unsigned char data_alignment_indicator : 1;
	unsigned char copyright : 1;
	unsigned char original_or_copy : 1;

	unsigned char PTS_DTS_flags : 2;
	unsigned char ESCR_flag : 1;
    unsigned char ES_rate_flag : 1;
	unsigned char DSM_trick_mode_flag : 1;
	unsigned char additional_copy_info_flag : 1;
	unsigned char PES_CRC_flag : 1;
	unsigned char PES_extension_flag : 1;
	unsigned char PES_header_data_length;
};

class ts_gop_cache {
public:
    ts_gop_cache();
    ~ts_gop_cache();

    void save_gop_cache(char* data_p, int data_len, std::string streamid);
    int send_gop_cache(std::string streamid, SRTSOCKET dst_srtsocket);

private:
    int get_pat_info(char* data_p, int data_len, ts_pat_info_t& pat_info);
    int get_pmt_info(char* data_p, int data_len, ts_pmt_info_t& pmt_info);
	bool pes_is_iframe(char* data_p, int data_len, ts_pes_header& pes_header_info);

	void clear_media_packet(std::string streamid);
    void insert_media_packet(std::string streamid, char* data_p, int data_len);

private:
    char _pat_p[MPEG_TS_SIZE];
    char _pmt_p[MPEG_TS_SIZE];
    ts_pat_info_t _pat_info;
    ts_pmt_info_t _pmt_info;
    std::unordered_map<std::string, std::list<std::shared_ptr<Media_Packet>>> _packet_map;
};

}
#endif //TS_GOP_CACHE_H
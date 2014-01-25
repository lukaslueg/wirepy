import cffi
from .. import platform

iface = cffi.FFI()


def decoded_string(cdata, maxlen=-1):
    return iface._string(cdata, maxlen).decode(errors='replace')  # TODO
iface._string, iface.string = iface.string, decoded_string

iface.cdef('''
            /*
                misc / util
            */
            typedef long int time_t;

            /*
                glib.h
            */
            typedef unsigned int guint;
            typedef int gint;
            typedef gint gboolean;
            typedef void* gpointer;
            typedef const void *gconstpointer;
            typedef char gchar;
            typedef unsigned char guchar;
            typedef long glong;
            typedef unsigned long gulong;
            typedef signed char gint8;
            typedef unsigned char guint8;
            typedef signed short gint16;
            typedef unsigned short guint16;
            typedef signed int gint32;
            typedef unsigned int guint32;
           ''')

iface.cdef('''
            typedef signed %s gint64;
            typedef unsigned %s guint64;
           ''' % (platform.GINT64TYPE, platform.GINT64TYPE))

iface.cdef('''
            typedef double gdouble;
            typedef unsigned long gsize;
            typedef signed long gssize;

            typedef struct {
                char *str;
                gsize len;
                gsize allocated_len;
            } GString;

            typedef struct {
                gchar *data;
                guint len;
            } GArray;

            typedef struct {
                guint8 *data;
                guint len;
            } GByteArray;

            typedef struct {
                gpointer *pdata;
                guint len;
            } GPtrArray;

            typedef struct _GSList GSList;
            struct _GSList {
                gpointer data;
                GSList *next;
            };

            typedef struct _GList GList;
            struct _GList {
                gpointer data;
                GList *next;
                GList *prev;
            };

            typedef gboolean (*GEqualFunc) (gconstpointer a, gconstpointer b);
            typedef guint (*GHashFunc) (gconstpointer key);
            struct GHashTableIter;

            typedef ... GRegex;
            typedef ... GHashTable;
            typedef ... GHashTableIter;

            void g_free(gpointer mem);

            GString* g_string_new(const gchar *init);
            GString* g_string_new_len(const gchar *init, gssize len);
            gchar* g_string_free(GString *string, gboolean free_segment);

            GHashTable* g_hash_table_new(GHashFunc hash_func, GEqualFunc key_equal_func);
            //GHashTable* g_hash_table_new_full(GHashFunc hash_func, GEqualFunc key_equal_func, GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func);
            void g_hash_table_insert(GHashTable *hash_table, gpointer key, gpointer value);
            void g_hash_table_replace(GHashTable *hash_table, gpointer key, gpointer value);
            guint g_hash_table_size(GHashTable *hash_table);
            gpointer g_hash_table_lookup(GHashTable *hash_table, gconstpointer key);
            gboolean g_hash_table_remove(GHashTable *hash_table, gconstpointer key);
            void g_hash_table_destroy(GHashTable *hash_table);
            void g_hash_table_iter_init(GHashTableIter *iter, GHashTable *hash_table);
            gboolean g_hash_table_iter_next(GHashTableIter *iter, gpointer *key, gpointer *value);

            GList* g_list_alloc();
            GList* g_list_append(GList *list, gpointer data);
            void g_list_free(GList *list);
            guint g_list_length(GList *list);
            GList* g_list_nth(GList *list, guint n);

            GSList* g_slist_alloc();
            GSList* g_slist_append(GSList *list, gpointer data);
            void g_slist_free(GSList *list);
            guint g_slist_length(GSList *list);


            /*
                wiretap/wtap.h
            */
            #define WTAP_FILE_TSPREC_SEC ...
            #define WTAP_FILE_TSPREC_DSEC ...
            #define WTAP_FILE_TSPREC_CSEC ...
            #define WTAP_FILE_TSPREC_MSEC ...
            #define WTAP_FILE_TSPREC_USEC ...
            #define WTAP_FILE_TSPREC_NSEC ...
            #define WTAP_MAX_PACKET_SIZE ...

            #define WTAP_NUM_FILE_TYPES ...

            struct wtap;

            struct nstr_phdr {
                gint64 rec_offset;
                gint32 rec_len;
                guint8 nicno_offset;
                guint8 nicno_len;
                guint8 dir_offset;
                guint8 dir_len;
                guint8 eth_offset;
                guint8 pcb_offset;
                guint8 l_pcb_offset;
                guint8 rec_type;
                guint8 vlantag_offset;
                guint8 coreid_offset;
                guint8 srcnodeid_offset;
                guint8 destnodeid_offset;
                guint8 clflags_offset;
            };

            struct eth_phdr {
                gint fcs_len;
            };

            struct x25_phdr {
                guint8 flags;
            };

            struct isdn_phdr {
                gboolean uton;
                guint8 channel;
            };

            struct atm_phdr {
                guint32 flags;
                guint8 aal;
                guint8 type;
                guint8 subtype;
                guint16 vpi;
                guint16 vci;
                guint8 aal2_cid;
                guint16 channel;
                guint16 cells;
                guint16 aal5t_u2u;
                guint16 aal5t_len;
                guint32 aal5t_chksum;
            };

            struct ascend_phdr {
                guint16 type;
                char user[64];
                guint32 sess;
                char call_num[64];
                guint32 chunk;
                guint32 task;
            };

            struct p2p_phdr {
                int sent;
            };

            struct ieee_802_11_phdr {
                gint fcs_len;
                gboolean decrypted;
                guint8 channel;
                guint16 data_rate;
                guint8 signal_level;
            };

            struct cosine_phdr {
                guint8 encap;
                guint8 direction;
                char if_name[128];
                guint16 pro;
                guint16 off;
                guint16 pri;
                guint16 rm;
                guint16 err;
            };

            struct irda_phdr {
                guint16 pkttype;
            };

            struct nettl_phdr {
                guint16 subsys;
                guint32 devid;
                guint32 kind;
                gint32 pid;
                guint16 uid;
            };

            struct mtp2_phdr {
                guint8 sent;
                guint8 annex_a_used;
                guint16 link_number;
            };

            typedef union {
                struct {
                    guint16 vp;
                    guint16 vc;
                    guint16 cid;
                } atm;
                guint32 ds0mask;
            } k12_input_info_t;

            struct k12_phdr {
                guint32 input;
                const gchar* input_name;
                const gchar* stack_file;
                guint32 input_type;
                k12_input_info_t input_info;
                guint8* extra_info;
                guint32 extra_length;
                void* stuff;
            };

            struct lapd_phdr {
                guint16 pkttype;
                guint8 we_network;
            };

            struct wtap;
            struct catapult_dct2000_phdr
            {
                union
                {
                    struct isdn_phdr isdn;
                    struct atm_phdr atm;
                    struct p2p_phdr p2p;
                } inner_pseudo_header;
                gint64 seek_off;
                struct wtap *wth;
            };

            struct libpcap_bt_phdr {
                guint32 direction;
            };

            struct libpcap_ppp_phdr {
                guint8 direction;
            };

            struct erf_phdr {
                guint64 ts;
                guint8 type;
                guint8 flags;
                guint16 rlen;
                guint16 lctr;
                guint16 wlen;
            };

            struct erf_ehdr {
                guint64 ehdr;
            };

            struct erf_mc_phdr {
                struct erf_phdr phdr;
                struct erf_ehdr ehdr_list[8];
                union
                {
                    guint16 eth_hdr;
                    guint32 mc_hdr;
                } subhdr;
            };

            struct llcp_phdr {
                guint8 adapter;
                guint8 flags;
            };

            struct sita_phdr {
                guint8 sita_flags;
                guint8 sita_signals;
                guint8 sita_errors1;
                guint8 sita_errors2;
                guint8 sita_proto;
            };

            struct bthci_phdr {
                gboolean sent;
                guint8 channel;
            };

            struct l1event_phdr {
                gboolean uton;
            };

            struct i2c_phdr {
                guint8 is_event;
                guint8 bus;
                guint32 flags;
            };

            struct gsm_um_phdr {
                gboolean uplink;
                guint8 channel;
                guint8 bsic;
                guint16 arfcn;
                guint32 tdma_frame;
                guint8 error;
                guint16 timeshift;
            };

            union wtap_pseudo_header {
                struct eth_phdr eth;
                struct x25_phdr x25;
                struct isdn_phdr isdn;
                struct atm_phdr atm;
                struct ascend_phdr ascend;
                struct p2p_phdr p2p;
                struct ieee_802_11_phdr ieee_802_11;
                struct cosine_phdr cosine;
                struct irda_phdr irda;
                struct nettl_phdr nettl;
                struct mtp2_phdr mtp2;
                struct k12_phdr k12;
                struct lapd_phdr lapd;
                struct catapult_dct2000_phdr dct2000;
                struct erf_mc_phdr erf;
                struct sita_phdr sita;
                struct bthci_phdr bthci;
                struct l1event_phdr l1event;
                struct i2c_phdr i2c;
                struct gsm_um_phdr gsm_um;
                struct nstr_phdr nstr;
                struct llcp_phdr llcp;
            };

            struct wtap_nstime {
                time_t secs;
                int nsecs;
            };

            struct wtap_pkthdr {
                guint32 presence_flags;
                struct wtap_nstime ts;
                guint32 caplen;
                guint32 len;
                int pkt_encap;
                guint32 interface_id;
                gchar *opt_comment;
                guint64 drop_count;
                guint32 pack_flags;
                union wtap_pseudo_header pseudo_header;
            };

            #define WTAP_HAS_TS ...
            #define WTAP_HAS_CAP_LEN ...
            #define WTAP_HAS_INTERFACE_ID ...
            #define WTAP_HAS_COMMENTS ...
            #define WTAP_HAS_DROP_COUNT ...
            #define WTAP_HAS_PACK_FLAGS ...

            typedef struct wtapng_section_s {
                guint64 section_length;
                gchar *opt_comment;
                gchar *shb_hardware;
                gchar *shb_os;
                const gchar *shb_user_appl;
            } wtapng_section_t;

            typedef struct wtap wtap;

            struct wtap* wtap_open_offline(const char* filename, int *err, gchar **err_info, gboolean do_random);
            void wtap_cleareof(wtap *wth);
            gboolean wtap_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset);
            gboolean wtap_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, guint8 *pd, int len, int *err, gchar **err_info);
            struct wtap_pkthdr *wtap_phdr(wtap *wth);
            guint8 *wtap_buf_ptr(wtap *wth);
            gint64 wtap_read_so_far(wtap *wth);
            gint64 wtap_file_size(wtap *wth, int *err);
            gboolean wtap_iscompressed(wtap *wth);
            guint wtap_snapshot_length(wtap *wth);
            int wtap_file_type(wtap *wth);
            int wtap_file_encap(wtap *wth);
            int wtap_file_tsprecision(wtap *wth);
            wtapng_section_t* wtap_file_get_shb_info(wtap *wth);
            //wtapng_iface_descriptions_t *wtap_file_get_idb_info(wtap *wth);
            void wtap_write_shb_comment(wtap *wth, gchar *comment);
            void wtap_fdclose(wtap *wth);
            void wtap_sequential_close(wtap *wth);
            void wtap_close(wtap *wth);
            gboolean wtap_dump_can_open(int filetype);
            // TODO gboolean wtap_dump_can_write_encap(int filetype, int encap);
            gboolean wtap_dump_can_compress(int filetype);
            const char *wtap_file_type_string(int filetype);
            const char *wtap_file_type_short_string(int filetype);
            int wtap_short_string_to_file_type(const char *short_name);
            const char *wtap_strerror(int err);
            int wtap_get_num_encap_types(void);
            int wtap_get_num_file_types(void);
            const char *wtap_default_file_extension(int filetype);
            GSList *wtap_get_file_extensions_list(int filetype, gboolean include_compressed);
            void wtap_free_file_extensions_list(GSList *extensions);
            const char *wtap_encap_string(int encap);
            const char *wtap_encap_short_string(int encap);
            int wtap_short_string_to_encap(const char *short_name);

            #define WTAP_ERR_NOT_REGULAR_FILE ...
            #define WTAP_ERR_RANDOM_OPEN_PIPE ...
            #define WTAP_ERR_FILE_UNKNOWN_FORMAT ...
            #define WTAP_ERR_UNSUPPORTED ...
            #define WTAP_ERR_CANT_WRITE_TO_PIPE ...
            #define WTAP_ERR_CANT_OPEN ...
            #define WTAP_ERR_UNSUPPORTED_FILE_TYPE ...
            #define WTAP_ERR_UNSUPPORTED_ENCAP ...
            #define WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED ...
            #define WTAP_ERR_CANT_CLOSE ...
            #define WTAP_ERR_CANT_READ ...
            #define WTAP_ERR_SHORT_READ ...
            #define WTAP_ERR_BAD_FILE ...
            #define WTAP_ERR_SHORT_WRITE ...
            #define WTAP_ERR_UNC_TRUNCATED ...
            #define WTAP_ERR_UNC_OVERFLOW ...
            #define WTAP_ERR_UNC_BAD_OFFSET ...
            #define WTAP_ERR_RANDOM_OPEN_STDIN ...
            #define WTAP_ERR_COMPRESSION_NOT_SUPPORTED ...
            #define WTAP_ERR_CANT_SEEK ...
            #define WTAP_ERR_DECOMPRESS ...
            #define WTAP_ERR_INTERNAL ...

            /*
                epan/nstime.h
            */
            typedef struct {
                time_t secs;
                int nsecs;
            } nstime_t;

            /*
                frame_data.h
            */
            typedef struct _frame_data {
                GSList *pfd;
                guint32 num;
                guint32 interface_id;
                guint32 pack_flags;
                guint32 pkt_len;
                guint32 cap_len;
                guint32 cum_bytes;
                gint64 file_off;
                guint16 subnum;
                gint16 lnk_t;
                struct {
                    unsigned int passed_dfilter : 1;
                    unsigned int dependent_of_displayed : 1;
                    unsigned int encoding : 2;
                    unsigned int visited : 1;
                    unsigned int marked : 1;
                    unsigned int ref_time : 1;
                    unsigned int ignored : 1;
                    unsigned int has_ts : 1;
                    unsigned int has_if_id : 1;
                    unsigned int has_pack_flags : 1;
                } flags;
                const void *color_filter;
                nstime_t abs_ts;
                nstime_t shift_offset;
                nstime_t rel_ts;
                const struct _frame_data *prev_dis;
                const struct _frame_data *prev_cap;
                gchar        *opt_comment;
            } frame_data;

            gint frame_data_compare(const frame_data *fdata1, const frame_data *fdata2, int field);
            void frame_data_destroy(frame_data *fdata);
            void frame_data_init(frame_data *fdata, guint32 num, const struct wtap_pkthdr *phdr, gint64 offset, guint32 cum_bytes);
            void frame_data_set_before_dissect(frame_data *fdata, nstime_t *elapsed_time, nstime_t *first_ts, const frame_data *prev_dis, const frame_data *prev_cap);
            void frame_data_set_after_dissect(frame_data *fdata, guint32 *cum_bytes);

            /*
                register.h
            */
            typedef enum {
                RA_NONE=...,
                RA_DISSECTORS=...,
                RA_LISTENERS=...,
                RA_REGISTER=...,
                RA_PLUGIN_REGISTER=...,
                RA_PYTHON_REGISTER=...,
                RA_HANDOFF=...,
                RA_PLUGIN_HANDOFF=...,
                RA_PYTHON_HANDOFF=...,
                RA_LUA_PLUGINS=...,
                RA_PREFERENCES=...,
                RA_CONFIGURATION=...
                , ...
            } register_action_e;


            /*
                epan/epan.h
            */
            void epan_cleanup(void);

            /*
                epan/tfs.h
            */
            typedef struct true_false_string {
                const char *true_string;
                const char *false_string;
            } true_false_string;


            /*
                epan/value_string.h
            */
            typedef struct _value_string {
                guint32 value;
                const gchar *strptr;
            } value_string;

            typedef struct _range_string {
                guint32 value_min;
                guint32 value_max;
                const gchar *strptr;
            } range_string;

            typedef struct _value_string_ext {
                guint32 _vs_num_entries;
                const value_string* _vs_p;
                const gchar* _vs_name;
                ...;
            } value_string_ext;

            extern const gchar* try_val_to_str_ext(const guint32 val, const value_string_ext *vse);


            /*
                epan/dfilter/dfilter.h
            */
            typedef struct _dfilter_t dfilter_t;
            //extern const gchar *dfilter_error_msg;
            const char* wrapped_dfilter_get_error_msg(void);
            gboolean dfilter_compile(const gchar *text, dfilter_t **dfp);
            void dfilter_free(dfilter_t *df);
            void dfilter_dump(dfilter_t *df);


            /*
                epan/ipv4.h
            */
            typedef struct {
                guint32 addr;
                guint32 nmask;
            } ipv4_addr;

            /*
                epan/ipv6.h
            */
            struct e_in6_addr {
                guint8 bytes[16];
            };
            typedef struct {
                struct e_in6_addr addr;
                guint32 prefix;
            } ipv6_addr;

            /*
                epan/guid-utils.h
            */
            #define GUID_LEN ...
            typedef struct _e_guid_t {
                guint32 data1;
                guint16 data2;
                guint16 data3;
                guint8 data4[8];
            } e_guid_t;
            extern void guids_init(void);
            extern void guids_add_guid(e_guid_t *guid, const gchar *name);
            extern const gchar *guids_get_guid_name(e_guid_t *guid);
            extern const gchar* guids_resolve_guid_to_str(e_guid_t *guid);


            /*
                epan/tvbuff.h
            */
            typedef enum {
                TVBUFF_REAL_DATA=...,
                TVBUFF_SUBSET=...,
                TVBUFF_COMPOSITE=...
            } tvbuff_type;
            typedef struct tvbuff tvbuff_t;


            /*
                epan/ftypes/ftypes.h
            */
            enum ftenum {
                FT_NONE=...,
                FT_PROTOCOL=...,
                FT_BOOLEAN=...,
                FT_UINT8=...,
                FT_UINT16=...,
                FT_UINT24=...,
                FT_UINT32=...,
                FT_UINT64=...,
                FT_INT8=...,
                FT_INT16=...,
                FT_INT24=...,
                FT_INT32=...,
                FT_INT64=...,
                FT_FLOAT=...,
                FT_DOUBLE=...,
                FT_ABSOLUTE_TIME=...,
                FT_RELATIVE_TIME=...,
                FT_STRING=...,
                FT_STRINGZ=...,
                FT_UINT_STRING=...,
                FT_ETHER=...,
                FT_BYTES=...,
                FT_UINT_BYTES=...,
                FT_IPv4=...,
                FT_IPv6=...,
                FT_IPXNET=...,
                FT_FRAMENUM=...,
                FT_PCRE=...,
                FT_GUID=...,
                FT_OID=...,
                FT_EUI64=...,
                FT_NUM_TYPES=...,
                ...
            };

            #define FT_ETHER_LEN ...
            #define FT_GUID_LEN ...
            #define FT_IPv4_LEN ...
            #define FT_IPv6_LEN ...
            #define FT_IPXNET_LEN ...
            #define FT_EUI64_LEN ...

            typedef enum ftenum ftenum_t;
            typedef struct _ftype_t ftype_t;

            enum ftrepr {
                FTREPR_DISPLAY=...,
                FTREPR_DFILTER=...,
                ...
            };
            typedef enum ftrepr ftrepr_t;

            const char* ftype_name(ftenum_t ftype);
            const char* ftype_pretty_name(ftenum_t ftype);
            gboolean ftype_can_slice(enum ftenum ftype);
            gboolean ftype_can_eq(enum ftenum ftype);
            gboolean ftype_can_ne(enum ftenum ftype);
            gboolean ftype_can_gt(enum ftenum ftype);
            gboolean ftype_can_ge(enum ftenum ftype);
            gboolean ftype_can_lt(enum ftenum ftype);
            gboolean ftype_can_le(enum ftenum ftype);
            gboolean ftype_can_contains(enum ftenum ftype);
            gboolean ftype_can_matches(enum ftenum ftype);

            typedef struct _fvalue_t {
                ftype_t *ftype;
                union {
                    guint32 uinteger;
                    gint32 sinteger;
                    guint64 integer64;
                    gdouble floating;
                    gchar *string;
                    guchar *ustring;
                    GByteArray *bytes;
                    ipv4_addr ipv4;
                    ipv6_addr ipv6;
                    e_guid_t guid;
                    nstime_t time;
                    tvbuff_t *tvb;
                    GRegex *re;
                } value;
                gboolean fvalue_gboolean1;
            } fvalue_t;

            typedef void (*FvalueNewFunc)(fvalue_t*);
            typedef void (*FvalueFreeFunc)(fvalue_t*);
            typedef void (*LogFunc)(const char*, ...);

            typedef gboolean (*FvalueFromUnparsed)(fvalue_t*, char*, gboolean, LogFunc);
            typedef gboolean (*FvalueFromString)(fvalue_t*, char*, LogFunc);
            typedef void (*FvalueToStringRepr)(fvalue_t*, ftrepr_t, char*);
            typedef int (*FvalueStringReprLen)(fvalue_t*, ftrepr_t);

            typedef void (*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
            typedef void (*FvalueSetUnsignedIntegerFunc)(fvalue_t*, guint32);
            typedef void (*FvalueSetSignedIntegerFunc)(fvalue_t*, gint32);
            typedef void (*FvalueSetInteger64Func)(fvalue_t*, guint64);
            typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

            typedef gpointer (*FvalueGetFunc)(fvalue_t*);
            typedef guint32 (*FvalueGetUnsignedIntegerFunc)(fvalue_t*);
            typedef gint32 (*FvalueGetSignedIntegerFunc)(fvalue_t*);
            typedef guint64 (*FvalueGetInteger64Func)(fvalue_t*);
            typedef double (*FvalueGetFloatingFunc)(fvalue_t*);

            typedef gboolean (*FvalueCmp)(const fvalue_t*, const fvalue_t*);

            typedef guint (*FvalueLen)(fvalue_t*);
            typedef void (*FvalueSlice)(fvalue_t*, GByteArray*, guint offset, guint length);

            struct _ftype_t {
                ftenum_t ftype;
                const char *name;
                const char *pretty_name;
                int wire_size;
                FvalueNewFunc new_value;
                FvalueFreeFunc free_value;
                FvalueFromUnparsed val_from_unparsed;
                FvalueFromString val_from_string;
                FvalueToStringRepr val_to_string_repr;
                FvalueStringReprLen len_string_repr;
                FvalueSetFunc set_value;
                FvalueSetUnsignedIntegerFunc set_value_uinteger;
                FvalueSetSignedIntegerFunc set_value_sinteger;
                FvalueSetInteger64Func set_value_integer64;
                FvalueSetFloatingFunc set_value_floating;
                FvalueGetFunc get_value;
                FvalueGetUnsignedIntegerFunc get_value_uinteger;
                FvalueGetSignedIntegerFunc get_value_sinteger;
                FvalueGetInteger64Func get_value_integer64;
                FvalueGetFloatingFunc get_value_floating;
                FvalueCmp cmp_eq;
                FvalueCmp cmp_ne;
                FvalueCmp cmp_gt;
                FvalueCmp cmp_ge;
                FvalueCmp cmp_lt;
                FvalueCmp cmp_le;
                FvalueCmp cmp_bitwise_and;
                FvalueCmp cmp_contains;
                FvalueCmp cmp_matches;
                FvalueLen len;
                FvalueSlice slice;
            };

            fvalue_t* fvalue_from_unparsed(ftenum_t ftype, char *s, gboolean allow_partial_value, LogFunc logfunc);

            int fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype);
            extern char* fvalue_to_string_repr(fvalue_t *fv, ftrepr_t rtype, char *buf);
            gpointer fvalue_get(fvalue_t *fv);
            extern guint32 fvalue_get_uinteger(fvalue_t *fv);
            extern gint32 fvalue_get_sinteger(fvalue_t *fv);
            guint64 fvalue_get_integer64(fvalue_t *fv);
            extern double fvalue_get_floating(fvalue_t *fv);


            /*
                epan/proto.h
            */
            #define ENC_BIG_ENDIAN ...
            #define ENC_LITTLE_ENDIAN ...
            #define ENC_TIME_TIMESPEC ...
            #define ENC_TIME_NTP ...
            #define ENC_CHARENCODING_MASK ...
            #define ENC_ASCII ...
            #define ENC_UTF_8 ...
            #define ENC_UTF_16 ...
            #define ENC_UCS_2 ...
            #define ENC_EBCDIC ...
            #define ENC_NA ...
            #define BASE_DISPLAY_E_MASK ...
            #define BASE_RANGE_STRING ...
            #define BASE_EXT_STRING ...
            #define FI_HIDDEN ...
            #define FI_GENERATED ...
            #define FI_URL ...
            #define FI_LITTLE_ENDIAN ...
            #define FI_BIG_ENDIAN ...
            #define PI_SEVERITY_MASK ...
            #define PI_COMMENT ...
            #define PI_CHAT ...
            #define PI_NOTE ...
            #define PI_WARN ...
            #define PI_ERROR ...
            #define PI_GROUP_MASK ...
            #define PI_CHECKSUM ...
            #define PI_SEQUENCE ...
            #define PI_RESPONSE_CODE ...
            #define PI_REQUEST_CODE ...
            #define PI_UNDECODED ...
            #define PI_REASSEMBLE ...
            #define PI_MALFORMED ...
            #define PI_DEBUG ...
            #define PI_PROTOCOL ...
            #define PI_SECURITY ...
            #define PI_COMMENTS_GROUP ...

            typedef enum {
                BASE_NONE=...,
                BASE_DEC=...,
                BASE_HEX=...,
                BASE_OCT=...,
                BASE_DEC_HEX=...,
                BASE_HEX_DEC=...,
                BASE_CUSTOM=...,
                ...
            } base_display_e;

            typedef enum {
                HF_REF_TYPE_NONE=...,
                HF_REF_TYPE_INDIRECT=...,
                HF_REF_TYPE_DIRECT=...,
                ...
            } hf_ref_type;

            typedef struct _header_field_info header_field_info;
            struct _header_field_info {
                const char *name;
                const char *abbrev;
                enum ftenum type;
                int display;
                const void *strings;
                guint32 bitmask;
                const char *blurb;
                int id;
                int parent;
                hf_ref_type ref_type;
                int bitshift;
                header_field_info *same_name_next;
                header_field_info *same_name_prev;
                ...;
            };

            #define ITEM_LABEL_LENGTH ...

            typedef struct _item_label_t {
                char representation[240]; // TODO
            } item_label_t;

            typedef struct field_info {
                header_field_info *hfinfo;
                gint start;
                gint length;
                gint appendix_start;
                gint appendix_length;
                gint tree_type;
                item_label_t *rep;
                guint32 flags;
                //tvbuff_t *ds_tvb;
                fvalue_t value;
                ...;
            } field_info;

            typedef struct {
                GHashTable *interesting_hfids;
                gboolean visible;
                gboolean fake_protocols;
                gint count;
                struct _packet_info *pinfo;
                field_info *fi_tmp;
            } tree_data_t;

            typedef struct _proto_node {
                struct _proto_node *first_child;
                struct _proto_node *last_child;
                struct _proto_node *next;
                struct _proto_node *parent;
                field_info *finfo;
                tree_data_t *tree_data;
            } proto_node;

            typedef proto_node proto_tree;
            typedef proto_node proto_item;

            extern int proto_registrar_n(void);
            extern const char* proto_registrar_get_abbrev(const int n);
            extern header_field_info* proto_registrar_get_nth(guint hfindex);
            extern header_field_info* proto_registrar_get_byname(const char *field_name);
            extern enum ftenum proto_registrar_get_ftype(const int n);
            extern int proto_registrar_get_parent(const int n);
            extern gboolean proto_registrar_is_protocol(const int n);

            typedef struct _protocol protocol_t;

            extern void proto_mark_private(const int proto_id);
            extern gboolean proto_is_private(const int proto_id);
            extern int proto_get_first_protocol(void **cookie);
            extern int proto_get_data_protocol(void *cookie);
            extern int proto_get_next_protocol(void **cookie);
            extern header_field_info *proto_get_first_protocol_field(const int proto_id, void **cookie);
            extern header_field_info *proto_get_next_protocol_field(void **cookie);
            extern int proto_get_id_by_filter_name(const gchar* filter_name);
            extern gboolean proto_can_toggle_protocol(const int proto_id);
            extern protocol_t *find_protocol_by_id(const int proto_id);
            extern const char *proto_get_protocol_name(const int proto_id);
            extern int proto_get_id(const protocol_t *protocol);
            extern const char *proto_get_protocol_short_name(const protocol_t *protocol);
            extern const char *proto_get_protocol_long_name(const protocol_t *protocol);
            extern gboolean proto_is_protocol_enabled(const protocol_t *protocol);
            extern const char *proto_get_protocol_filter_name(const int proto_id);
            extern void proto_set_decoding(const int proto_id, const gboolean enabled);
            extern void proto_enable_all(void);
            extern void proto_set_cant_toggle(const int proto_id);
            extern guchar proto_check_field_name(const gchar *field_name);

            int proto_item_get_len(const proto_item *pi);
            proto_tree *proto_item_get_subtree(const proto_item *pi);
            void proto_item_fill_label(field_info *fi, gchar *label_str);

            /*
                epan/packet_info.h
            */
            typedef struct _packet_info {
                ...;
            } packet_info;


            /*
                epan/epan_dissect.h
            */
            typedef struct _epan_dissect_t {
                //tvbuff_t *tvb;
                proto_tree *tree;
                packet_info pi;
                ...;
            } epan_dissect_t;


            /*
                epan/epan.h
            */
            struct _column_info;
            typedef struct _column_info column_info;

            gboolean dfilter_apply_edt(dfilter_t *df, epan_dissect_t* edt);

            epan_dissect_t* epan_dissect_init(epan_dissect_t *edt, const gboolean create_proto_tree, const gboolean proto_tree_visible);
            epan_dissect_t* epan_dissect_new(const gboolean create_proto_tree, const gboolean proto_tree_visibile);
            void epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols);
            void epan_dissect_run(epan_dissect_t *edt, struct wtap_pkthdr *phdr, const guint8* data, frame_data *fd, column_info *cinfo);
            void epan_dissect_prime_dfilter(epan_dissect_t *edt, const dfilter_t *dfcode);
            void epan_dissect_fill_in_columns(epan_dissect_t *edt, const gboolean fill_col_exprs, const gboolean fill_fd_columns);
            void epan_dissect_cleanup(epan_dissect_t* edt);
            void epan_dissect_free(epan_dissect_t* edt);


            typedef void (*register_cb)(register_action_e action, const char *message, gpointer client_data);
            extern void register_all_protocols(register_cb cb, gpointer client_data);
            extern void register_all_protocol_handoffs(register_cb cb, gpointer client_data);
            //extern void register_all_tap_listeners(void); // TODO
            extern gulong register_count(void);

            extern const gchar* epan_get_version(void);
            void epan_get_compiled_version_info(GString *str);


            /*
                epan/timestamp.h
            */
            typedef enum {
                TS_RELATIVE,
                TS_ABSOLUTE,
                TS_ABSOLUTE_WITH_DATE,
                TS_DELTA,
                TS_DELTA_DIS,
                TS_EPOCH,
                TS_UTC,
                TS_UTC_WITH_DATE,
                TS_NOT_SET,
                ...
            } ts_type;
            typedef enum {
                TS_PREC_AUTO,
                TS_PREC_FIXED_SEC,
                ...
            } ts_precision;
            typedef enum {
                TS_SECONDS_DEFAULT,
                TS_SECONDS_HOUR_MIN_SEC,
                TS_SECONDS_NOT_SET,
                ...
            } ts_seconds_type;

            extern ts_type timestamp_get_type(void);
            extern void timestamp_set_type(ts_type);

            extern int timestamp_get_precision(void);
            extern void timestamp_set_precision(int tsp);

            extern ts_seconds_type timestamp_get_seconds_type(void);
            extern void timestamp_set_seconds_type(ts_seconds_type);


            /*
                epan/packet.h
            */
            extern void init_dissection(void);
            extern void cleanup_dissection(void);


            /*
                epan/dfilter/drange.h
            */
            typedef struct _drange {
                GSList* range_list;
                gboolean has_total_length;
                gint total_length;
                gint min_start_offset;
                gint max_start_offset;
            } drange;


            /*
                epan/column_info.h
            */
            void col_setup(column_info *cinfo, const gint num_cols);

            #define COL_MAX_LEN ...
            #define COL_MAX_INFO_LEN ...

            typedef struct {
                const gchar **col_expr;
                gchar **col_expr_val;
            } col_expr_t;

            struct _column_info {
                gint num_cols;
                gint *col_fmt;
                gboolean **fmt_matx;
                gint *col_first;
                gint *col_last;
                gchar **col_title;
                gchar **col_custom_field;
                gint *col_custom_occurrence;
                gint *col_custom_field_id;
                struct _dfilter_t **col_custom_dfilter;
                const gchar **col_data;
                gchar **col_buf;
                int *col_fence;
                col_expr_t col_expr;
                gboolean writable;
            };

            enum wirepy_wrapped_col_formats {
                COL_8021Q_VLAN_ID=...,
                COL_ABS_DATE_TIME=...,
                COL_ABS_TIME=...,
                COL_CIRCUIT_ID=...,
                COL_DSTIDX=...,
                COL_SRCIDX=...,
                COL_VSAN=...,
                COL_CUMULATIVE_BYTES=...,
                COL_CUSTOM=...,
                COL_DCE_CALL=...,
                COL_DCE_CTX=...,
                COL_DELTA_TIME=...,
                COL_DELTA_CONV_TIME=...,
                COL_DELTA_TIME_DIS=...,
                COL_RES_DST=...,
                COL_UNRES_DST=...,
                COL_RES_DST_PORT=...,
                COL_UNRES_DST_PORT=...,
                COL_DEF_DST=...,
                COL_DEF_DST_PORT=...,
                COL_EXPERT=...,
                COL_IF_DIR=...,
                COL_OXID=...,
                COL_RXID=...,
                COL_FR_DLCI=...,
                COL_FREQ_CHAN=...,
                COL_BSSGP_TLLI=...,
                COL_HPUX_DEVID=...,
                COL_HPUX_SUBSYS=...,
                COL_DEF_DL_DST=...,
                COL_DEF_DL_SRC=...,
                COL_RES_DL_DST=...,
                COL_UNRES_DL_DST=...,
                COL_RES_DL_SRC=...,
                COL_UNRES_DL_SRC=...,
                COL_RSSI=...,
                COL_TX_RATE=...,
                COL_DSCP_VALUE=...,
                COL_INFO=...,
                COL_COS_VALUE=...,
                COL_RES_NET_DST=...,
                COL_UNRES_NET_DST=...,
                COL_RES_NET_SRC=...,
                COL_UNRES_NET_SRC=...,
                COL_DEF_NET_DST=...,
                COL_DEF_NET_SRC=...,
                COL_NUMBER=...,
                COL_PACKET_LENGTH=...,
                COL_PROTOCOL=...,
                COL_REL_TIME=...,
                COL_REL_CONV_TIME=...,
                COL_DEF_SRC=...,
                COL_DEF_SRC_PORT=...,
                COL_RES_SRC=...,
                COL_UNRES_SRC=...,
                COL_RES_SRC_PORT=...,
                COL_UNRES_SRC_PORT=...,
                COL_TEI=...,
                COL_UTC_DATE_TIME=...,
                COL_UTC_TIME=...,
                COL_CLS_TIME=...,
                NUM_COL_FMTS=...,
                ...
            };


            /*
                color.h
            */
            typedef struct {
                guint32 pixel;
                guint16 red;
                guint16 green;
                guint16 blue;
            } color_t;


            /*
                epan/prefs.h
            */
            typedef enum {
                ...
            } layout_type_e;

            typedef enum {
                ...
            } layout_pane_content_e;

            typedef enum {
                ...
            } console_open_e;

            typedef enum {
                version_welcome_only,
                version_title_only,
                version_both,
                version_neither
            } version_info_e;

            typedef enum {
                PREFS_SET_OK,
                PREFS_SET_SYNTAX_ERR,
                PREFS_SET_NO_SUCH_PREF,
                PREFS_SET_OBSOLETE,
                ...
            } prefs_set_pref_e;

            typedef enum {
                UPDATE_CHANNEL_DEVELOPMENT,
                UPDATE_CHANNEL_STABLE
            } software_update_channel_e;

            typedef struct _e_prefs {
                gint pr_format;
                gint pr_dest;
                const gchar *pr_file;
                const gchar *pr_cmd;
                GList *col_list;
                gint num_cols;
                color_t st_client_fg, st_client_bg, st_server_fg, st_server_bg;
                gboolean gui_altern_colors;
                gboolean gui_expert_composite_eyecandy;
                gboolean filter_toolbar_show_in_statusbar;
                gint gui_ptree_line_style;
                gint gui_ptree_expander_style;
                gboolean gui_hex_dump_highlight_style;
                gint gui_toolbar_main_style, gui_toolbar_filter_style;
                gchar *gui_gtk2_font_name, *gui_qt_font_name;
                color_t gui_marked_fg, gui_marked_bg, gui_ignored_fg, gui_ignored_bg;
                const gchar *gui_colorized_fg, *gui_colorized_bg;
                gboolean gui_geometry_save_position, gui_geometry_save_size;
                gboolean gui_geometry_save_maximized, gui_macosx_style;
                console_open_e gui_console_open;
                guint gui_recent_df_entries_max;
                guint gui_recent_files_count_max;
                guint gui_fileopen_style;
                gchar *gui_fileopen_dir;
                guint gui_fileopen_preview;
                gboolean gui_ask_unsaved, gui_find_wrap, gui_use_pref_save;
                gchar *gui_webbrowser, *gui_window_title;
                const gchar *gui_start_title;
                version_info_e gui_version_placement;
                gboolean gui_auto_scroll_on_expand;
                guint gui_auto_scroll_percentage;
                layout_type_e gui_layout_type;
                layout_pane_content_e gui_layout_content_1;
                layout_pane_content_e gui_layout_content_2;
                layout_pane_content_e gui_layout_content_3;
                gint console_log_level;
                gchar *capture_device;
                gchar *capture_devices_linktypes;
                gchar *capture_devices_descr;
                gchar *capture_devices_hide;
                gchar *capture_devices_monitor_mode;
                gchar *capture_devices_buffersize;
                gchar *capture_devices_snaplen;
                gchar *capture_devices_pmode;
                gboolean capture_prom_mode;
                gboolean capture_pcap_ng;
                gboolean capture_real_time;
                gboolean capture_auto_scroll;
                gboolean capture_show_info;
                GList *capture_columns;
                guint rtp_player_max_visible;
                guint tap_update_interval;
                gboolean display_hidden_proto_items;
                gpointer filter_expressions;
                gboolean gui_update_enabled;
                software_update_channel_e gui_update_channel;
                gint gui_update_interval;
            } e_prefs;

            void prefs_register_modules(void);
            void prefs_apply_all(void);
            extern e_prefs *read_prefs(int *, int *, char **, int *, int *, char **);
            // TODO extern void free_prefs(e_prefs *pr);
            extern prefs_set_pref_e prefs_set_pref(char *prefarg);
            // TODO extern void copy_prefs(e_prefs *dest, e_prefs *src);
            extern int write_prefs(char **pf_path_return);
            e_prefs prefs;


            /*
                epan/column.h
            */
            typedef struct _fmt_data {
                gchar *title;
                int fmt;
                gchar *custom_field;
                gint custom_occurrence;
                gboolean visible;
                gboolean resolved;
            } fmt_data;

            const gchar *col_format_to_string(const gint);
            const gchar *col_format_desc(const gint);
            gint get_column_format(const gint);
            void set_column_format(const gint, const gint);
            void get_column_format_matches(gboolean *, const gint);
            gint get_column_format_from_str(const gchar*);
            gchar *get_column_title(const gint);
            void set_column_title(const gint, const gchar *);
            gboolean get_column_visible(const gint);
            void set_column_visible(const gint, gboolean);
            gboolean get_column_resolved(const gint);
            void set_column_resolved(const gint, gboolean);
            const gchar *get_column_custom_field(const gint);
            void set_column_custom_field(const gint, const char*);
            gint get_column_custom_occurrence(const gint);
            void set_column_custom_occurrence(const gint, const gint);
            const gchar *get_column_width_string(const gint, const gint);
            const char *get_column_longest_string(const gint);
            gint get_column_char_width(const gint format);

            void build_column_format_array(column_info *cinfo, const gint num_cols, const gboolean reset_fences);

            /*
                epan/column-utils.h
            */
            gboolean have_custom_cols(column_info *cinfo);
            void col_custom_prime_edt(epan_dissect_t *edt, column_info *cinfo);

            /*
                wsutil/privileges.h
            */
            extern void init_process_policies(void);
            extern gboolean started_with_special_privs(void);
            extern gboolean running_with_special_privs(void);
            extern void relinquish_special_privs_perm(void);
            extern gchar *get_cur_username(void);
            extern gchar *get_cur_groupname(void);


            /*
                own functions and wrappers
            */
            static const int COLUMN_FORMATS;
            static int WIREPY_EPAN_INITIALIZED;
            static int WIREPY_INIT_PROCESS_POLICIES_CALLED;


            static void (*logfunc_python_callback)(char *msg, int size);
            static void logfunc_wrapper(const char *msg, ...);


            void wrapped_epan_init(void (*report_open_failure_fcn_p)(const char *, int, gboolean),
                                   void (*report_read_failure_fcn_p)(const char *, int),
                                   void (*report_write_failure_fcn_p)(const char *, int));
            void (*failure_message)(const char *msg, int size);

            gboolean wrapped_proto_item_is_hidden(proto_item *);
         ''')

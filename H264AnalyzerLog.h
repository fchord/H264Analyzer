

/**
 * Print no output.
 */
#define AN_LOG_QUIET    -8

/**
 * Something went really wrong and we will crash now.
 */
#define AN_LOG_PANIC     0

/**
 * Something went wrong and recovery is not possible.
 * For example, no header was found for a format which depends
 * on headers or an illegal combination of parameters is used.
 */
#define AN_LOG_FATAL     8

/**
 * Something went wrong and cannot losslessly be recovered.
 * However, not all future data is affected.
 */
#define AN_LOG_ERROR    16

/**
 * Something somehow does not look correct. This may or may not
 * lead to problems. An example would be the use of '-vstrict -2'.
 */
#define AN_LOG_WARNING  24

/**
 * Standard information.
 */
#define AN_LOG_INFO     32

/**
 * Detailed information.
 */
#define AN_LOG_VERBOSE  40

/**
 * Stuff which is only useful for libav* developers.
 */
#define AN_LOG_DEBUG    48

/**
 * Extremely verbose debugging, useful for libav* development.
 */
#define AN_LOG_TRACE    56

#define H264MODULE_NAL "MODULE_NAL"
#define H264MODULE_SPS "MODULE_SPS"
#define H264MODULE_SPS_EXT "MODULE_SPS_EXT"
#define H264MODULE_PPS "MODULE_PPS"
#define H264MODULE_SLICE_HEADER "MODULE_SLICE_HEADER"
#define H264MODULE_SLICE_DATA "MODULE_SLICE_DATA"
#define H264MODULE_MACROBLOCK "MODULE_MACROBLOCK"
#define H264MODULE_REF_PIC "MODULE_REF_PIC"
#define H264MODULE_UNKOWN "MODULE_UNKOWN"

#define PRINTF_BUF_LEN 1024


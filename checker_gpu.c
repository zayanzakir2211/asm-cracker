/*
 * checker_gpu.c - GPU SHA-256 brute-force engine (OpenCL)
 *
 * Companion to checker_test.asm (the CPU/assembly engine). Speaks the
 * same stdout protocol so the existing Node.js GUI can drive either
 * engine interchangeably.
 *
 * Design goal: zero external SDK dependency. This file declares the
 * small subset of the OpenCL host API it needs itself, and loads
 * OpenCL.dll at runtime via LoadLibraryA/GetProcAddress. Any machine
 * with a GPU driver installed (NVIDIA, AMD, Intel Arc, Intel iGPU)
 * already ships OpenCL.dll, so nothing beyond a plain C compiler is
 * required to build this.
 *
 * Build (MinGW-w64, no OpenCL SDK needed):
 *   gcc checker_gpu.c -O2 -o checker_gpu.exe
 *
 * Usage:
 *   checker_gpu.exe list
 *   checker_gpu.exe brute <target_hex64> <charset> <minlen> <maxlen> <device_index>
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ===================== Minimal OpenCL host API ======================
 * Hand-declared subset of the Khronos OpenCL 1.2 host API - just the
 * types, constants and function signatures this program calls. Values
 * match the public cl.h header exactly (these are fixed interface
 * constants, not implementation-specific).
 * ===================================================================*/

typedef int32_t   cl_int;
typedef uint32_t  cl_uint;
typedef uint64_t  cl_ulong;
typedef uint64_t  cl_bitfield;
typedef cl_bitfield cl_device_type;
typedef cl_uint   cl_platform_info;
typedef cl_uint   cl_device_info;
typedef cl_bitfield cl_mem_flags;
typedef intptr_t  cl_context_properties;
typedef cl_uint   cl_program_build_info;
typedef cl_bitfield cl_command_queue_properties;
typedef cl_uint   cl_bool;

typedef void* cl_platform_id;
typedef void* cl_device_id;
typedef void* cl_context;
typedef void* cl_command_queue;
typedef void* cl_program;
typedef void* cl_kernel;
typedef void* cl_mem;
typedef void* cl_event;

#define CL_SUCCESS                      0
#define CL_TRUE                         1
#define CL_FALSE                        0

#define CL_DEVICE_TYPE_CPU              (1u << 1)
#define CL_DEVICE_TYPE_GPU              (1u << 2)
#define CL_DEVICE_TYPE_ACCELERATOR      (1u << 3)
#define CL_DEVICE_TYPE_ALL              0xFFFFFFFFu

#define CL_PLATFORM_NAME                0x0902

#define CL_DEVICE_TYPE                  0x1000
#define CL_DEVICE_MAX_COMPUTE_UNITS     0x1002
#define CL_DEVICE_MAX_CLOCK_FREQUENCY   0x100C
#define CL_DEVICE_GLOBAL_MEM_SIZE       0x101F
#define CL_DEVICE_NAME                  0x102B

#define CL_CONTEXT_PLATFORM             0x1084

#define CL_PROGRAM_BUILD_LOG            0x1183

#define CL_MEM_READ_WRITE               (1u << 0)
#define CL_MEM_WRITE_ONLY               (1u << 1)
#define CL_MEM_READ_ONLY                (1u << 2)
#define CL_MEM_COPY_HOST_PTR            (1u << 5)

typedef cl_int (*PFN_clGetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*);
typedef cl_int (*PFN_clGetPlatformInfo)(cl_platform_id, cl_platform_info, size_t, void*, size_t*);
typedef cl_int (*PFN_clGetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
typedef cl_int (*PFN_clGetDeviceInfo)(cl_device_id, cl_device_info, size_t, void*, size_t*);
typedef cl_context (*PFN_clCreateContext)(const cl_context_properties*, cl_uint, const cl_device_id*, void*, void*, cl_int*);
typedef cl_command_queue (*PFN_clCreateCommandQueue)(cl_context, cl_device_id, cl_command_queue_properties, cl_int*);
typedef cl_program (*PFN_clCreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
typedef cl_int (*PFN_clBuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*);
typedef cl_int (*PFN_clGetProgramBuildInfo)(cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*);
typedef cl_kernel (*PFN_clCreateKernel)(cl_program, const char*, cl_int*);
typedef cl_mem (*PFN_clCreateBuffer)(cl_context, cl_mem_flags, size_t, void*, cl_int*);
typedef cl_int (*PFN_clSetKernelArg)(cl_kernel, cl_uint, size_t, const void*);
typedef cl_int (*PFN_clEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*PFN_clEnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*PFN_clEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*PFN_clFinish)(cl_command_queue);
typedef cl_int (*PFN_clReleaseMemObject)(cl_mem);
typedef cl_int (*PFN_clReleaseKernel)(cl_kernel);
typedef cl_int (*PFN_clReleaseProgram)(cl_program);
typedef cl_int (*PFN_clReleaseCommandQueue)(cl_command_queue);
typedef cl_int (*PFN_clReleaseContext)(cl_context);

static PFN_clGetPlatformIDs            p_clGetPlatformIDs;
static PFN_clGetPlatformInfo           p_clGetPlatformInfo;
static PFN_clGetDeviceIDs              p_clGetDeviceIDs;
static PFN_clGetDeviceInfo             p_clGetDeviceInfo;
static PFN_clCreateContext             p_clCreateContext;
static PFN_clCreateCommandQueue        p_clCreateCommandQueue;
static PFN_clCreateProgramWithSource   p_clCreateProgramWithSource;
static PFN_clBuildProgram              p_clBuildProgram;
static PFN_clGetProgramBuildInfo       p_clGetProgramBuildInfo;
static PFN_clCreateKernel              p_clCreateKernel;
static PFN_clCreateBuffer              p_clCreateBuffer;
static PFN_clSetKernelArg              p_clSetKernelArg;
static PFN_clEnqueueWriteBuffer        p_clEnqueueWriteBuffer;
static PFN_clEnqueueNDRangeKernel      p_clEnqueueNDRangeKernel;
static PFN_clEnqueueReadBuffer         p_clEnqueueReadBuffer;
static PFN_clFinish                    p_clFinish;
static PFN_clReleaseMemObject          p_clReleaseMemObject;
static PFN_clReleaseKernel             p_clReleaseKernel;
static PFN_clReleaseProgram            p_clReleaseProgram;
static PFN_clReleaseCommandQueue       p_clReleaseCommandQueue;
static PFN_clReleaseContext            p_clReleaseContext;

static int load_opencl(void) {
    HMODULE h = LoadLibraryA("OpenCL.dll");
    if (!h) return 0;

    #define LOAD(name) \
        p_##name = (PFN_##name)GetProcAddress(h, #name); \
        if (!p_##name) return 0;

    LOAD(clGetPlatformIDs)
    LOAD(clGetPlatformInfo)
    LOAD(clGetDeviceIDs)
    LOAD(clGetDeviceInfo)
    LOAD(clCreateContext)
    LOAD(clCreateCommandQueue)
    LOAD(clCreateProgramWithSource)
    LOAD(clBuildProgram)
    LOAD(clGetProgramBuildInfo)
    LOAD(clCreateKernel)
    LOAD(clCreateBuffer)
    LOAD(clSetKernelArg)
    LOAD(clEnqueueWriteBuffer)
    LOAD(clEnqueueNDRangeKernel)
    LOAD(clEnqueueReadBuffer)
    LOAD(clFinish)
    LOAD(clReleaseMemObject)
    LOAD(clReleaseKernel)
    LOAD(clReleaseProgram)
    LOAD(clReleaseCommandQueue)
    LOAD(clReleaseContext)
    #undef LOAD

    return 1;
}

/* ===================== stdout protocol (matches checker_test.asm) ===== */

static void proto_error(const char* msg) {
    printf("ERROR %s\n", msg);
    fflush(stdout);
}
static void proto_progress(unsigned long long count) {
    printf("PROGRESS %llu\n", count);
    fflush(stdout);
}
static void proto_found(const char* candidate) {
    printf("FOUND %s\n", candidate);
    fflush(stdout);
}
static void proto_done(unsigned long long count) {
    printf("DONE %llu\n", count);
    fflush(stdout);
}
static void proto_device(int idx, const char* type, const char* name,
                          cl_uint cu, cl_uint clock_mhz, cl_ulong mem_bytes) {
    printf("DEVICE %d %s %s CU:%u CLOCK:%u MEM:%llu\n",
           idx, type, name, cu, clock_mhz,
           (unsigned long long)(mem_bytes / (1024 * 1024)));
    fflush(stdout);
}

/* ===================== device enumeration ============================ */

typedef struct {
    cl_platform_id platform;
    cl_device_id   device;
    char           name[256];
    cl_device_type type;
} DeviceEntry;

static int enumerate_devices(DeviceEntry* out, int max_out) {
    cl_platform_id platforms[16];
    cl_uint num_platforms = 0;
    int count = 0;

    if (p_clGetPlatformIDs(16, platforms, &num_platforms) != CL_SUCCESS)
        return 0;

    for (cl_uint pi = 0; pi < num_platforms; pi++) {
        cl_device_id devices[16];
        cl_uint num_devices = 0;
        if (p_clGetDeviceIDs(platforms[pi], CL_DEVICE_TYPE_ALL, 16, devices, &num_devices) != CL_SUCCESS)
            continue;

        for (cl_uint di = 0; di < num_devices && count < max_out; di++) {
            DeviceEntry* e = &out[count];
            e->platform = platforms[pi];
            e->device = devices[di];

            size_t len = 0;
            p_clGetDeviceInfo(devices[di], CL_DEVICE_NAME, sizeof(e->name) - 1, e->name, &len);
            e->name[len < sizeof(e->name) ? len : sizeof(e->name) - 1] = 0;

            p_clGetDeviceInfo(devices[di], CL_DEVICE_TYPE, sizeof(e->type), &e->type, NULL);

            count++;
        }
    }
    return count;
}

static void list_devices(void) {
    DeviceEntry devices[64];
    int n = enumerate_devices(devices, 64);
    if (n == 0) {
        proto_error("no_opencl_devices_found");
        return;
    }
    for (int i = 0; i < n; i++) {
        cl_uint cu = 0, clock_mhz = 0;
        cl_ulong mem = 0;
        p_clGetDeviceInfo(devices[i].device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cu), &cu, NULL);
        p_clGetDeviceInfo(devices[i].device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(clock_mhz), &clock_mhz, NULL);
        p_clGetDeviceInfo(devices[i].device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem), &mem, NULL);

        const char* type_str = "OTHER";
        if (devices[i].type & CL_DEVICE_TYPE_GPU) type_str = "GPU";
        else if (devices[i].type & CL_DEVICE_TYPE_CPU) type_str = "CPU";
        else if (devices[i].type & CL_DEVICE_TYPE_ACCELERATOR) type_str = "ACCELERATOR";

        proto_device(i, type_str, devices[i].name, cu, clock_mhz, mem);
    }
    proto_done((unsigned long long)n);
}

/* ===================== OpenCL SHA-256 brute-force kernel ============= */
/*
 * Single-block SHA-256 (message length 1..55 bytes, i.e. candidates
 * up to 55 chars - far beyond the 1-9 char range the GUI exposes).
 * Each work-item decodes its own candidate string from its global
 * index via mixed-radix expansion over the charset, hashes it, and
 * compares against the target digest.
 */
static const char* kernel_source =
"__constant uint K[64] = {\n"
"0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,\n"
"0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,\n"
"0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,\n"
"0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,\n"
"0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,\n"
"0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,\n"
"0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,\n"
"0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };\n"
"\n"
"__kernel void sha256_bruteforce(\n"
"    __global const uchar* charset,\n"
"    const uint charset_len,\n"
"    const uint length,\n"
"    const ulong base_offset,\n"
"    __constant uint* target,\n"
"    __global volatile uint* found_flag,\n"
"    __global ulong* found_index)\n"
"{\n"
"    ulong gid = (ulong)get_global_id(0);\n"
"    ulong idx = base_offset + gid;\n"
"\n"
"    uchar msg[64];\n"
"    for (int i = 0; i < 64; i++) msg[i] = 0;\n"
"\n"
"    ulong tmp = idx;\n"
"    for (int i = (int)length - 1; i >= 0; i--) {\n"
"        uint d = (uint)(tmp % (ulong)charset_len);\n"
"        tmp /= (ulong)charset_len;\n"
"        msg[i] = charset[d];\n"
"    }\n"
"\n"
"    msg[length] = 0x80;\n"
"    ulong bitlen = (ulong)length * 8ul;\n"
"    msg[56] = (uchar)(bitlen >> 56);\n"
"    msg[57] = (uchar)(bitlen >> 48);\n"
"    msg[58] = (uchar)(bitlen >> 40);\n"
"    msg[59] = (uchar)(bitlen >> 32);\n"
"    msg[60] = (uchar)(bitlen >> 24);\n"
"    msg[61] = (uchar)(bitlen >> 16);\n"
"    msg[62] = (uchar)(bitlen >> 8);\n"
"    msg[63] = (uchar)(bitlen);\n"
"\n"
"    uint w[64];\n"
"    for (int i = 0; i < 16; i++) {\n"
"        w[i] = ((uint)msg[i*4] << 24) | ((uint)msg[i*4+1] << 16) |\n"
"               ((uint)msg[i*4+2] << 8)  |  (uint)msg[i*4+3];\n"
"    }\n"
"    for (int i = 16; i < 64; i++) {\n"
"        uint x0 = w[i-15];\n"
"        uint s0 = rotate(x0, 25u) ^ rotate(x0, 14u) ^ (x0 >> 3);\n"
"        uint x1 = w[i-2];\n"
"        uint s1 = rotate(x1, 15u) ^ rotate(x1, 13u) ^ (x1 >> 10);\n"
"        w[i] = w[i-16] + s0 + w[i-7] + s1;\n"
"    }\n"
"\n"
"    uint a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;\n"
"    uint e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;\n"
"\n"
"    for (int i = 0; i < 64; i++) {\n"
"        uint S1 = rotate(e, 26u) ^ rotate(e, 21u) ^ rotate(e, 7u);\n"
"        uint ch = (e & f) ^ (~e & g);\n"
"        uint t1 = h + S1 + ch + K[i] + w[i];\n"
"        uint S0 = rotate(a, 30u) ^ rotate(a, 19u) ^ rotate(a, 10u);\n"
"        uint maj = (a & b) ^ (a & c) ^ (b & c);\n"
"        uint t2 = S0 + maj;\n"
"        h = g; g = f; f = e; e = d + t1;\n"
"        d = c; c = b; b = a; a = t1 + t2;\n"
"    }\n"
"\n"
"    uint h0 = 0x6a09e667 + a, h1 = 0xbb67ae85 + b, h2 = 0x3c6ef372 + c, h3 = 0xa54ff53a + d;\n"
"    uint h4 = 0x510e527f + e, h5 = 0x9b05688c + f, h6 = 0x1f83d9ab + g, h7 = 0x5be0cd19 + h;\n"
"\n"
"    if (h0==target[0] && h1==target[1] && h2==target[2] && h3==target[3] &&\n"
"        h4==target[4] && h5==target[5] && h6==target[6] && h7==target[7]) {\n"
"        uint old = atomic_cmpxchg(found_flag, 0u, 1u);\n"
"        if (old == 0u) {\n"
"            *found_index = idx;\n"
"        }\n"
"    }\n"
"}\n";

/* ===================== host-side helpers ============================= */

static int hex_to_words(const char* hex, uint32_t out[8]) {
    if (strlen(hex) != 64) return 0;
    for (int i = 0; i < 8; i++) {
        unsigned int v;
        if (sscanf(hex + i * 8, "%8x", &v) != 1) return 0;
        out[i] = (uint32_t)v;
    }
    return 1;
}

/* Reconstruct a candidate string from its numeric index (mirrors the
 * kernel's mixed-radix decode) - used once, after a match is found. */
static void decode_candidate(uint64_t idx, const char* charset, uint32_t charset_len,
                              uint32_t length, char* out) {
    uint64_t tmp = idx;
    for (int i = (int)length - 1; i >= 0; i--) {
        uint32_t d = (uint32_t)(tmp % charset_len);
        tmp /= charset_len;
        out[i] = charset[d];
    }
    out[length] = 0;
}

static uint64_t ipow(uint64_t base, uint32_t exp) {
    uint64_t r = 1;
    for (uint32_t i = 0; i < exp; i++) r *= base;
    return r;
}

#define BATCH_SIZE (16ull * 1024 * 1024)   /* candidates per kernel dispatch */
#define LOCAL_SIZE 256

static void brute_gpu(const char* target_hex, const char* charset,
                       uint32_t minlen, uint32_t maxlen, int device_index) {
    if (!load_opencl()) { proto_error("opencl_not_found"); return; }

    uint32_t target_words[8];
    if (!hex_to_words(target_hex, target_words)) { proto_error("bad_target_hash"); return; }

    uint32_t charset_len = (uint32_t)strlen(charset);
    if (charset_len == 0) { proto_error("empty_charset"); return; }
    if (maxlen > 55) { proto_error("maxlen_exceeds_single_block_limit_55"); return; }

    DeviceEntry devices[64];
    int n = enumerate_devices(devices, 64);
    if (n == 0) { proto_error("no_opencl_devices_found"); return; }
    if (device_index < 0 || device_index >= n) { proto_error("invalid_device_index"); return; }

    cl_int err;
    cl_device_id device = devices[device_index].device;
    cl_platform_id platform = devices[device_index].platform;

    cl_context_properties props[] = { CL_CONTEXT_PLATFORM, (cl_context_properties)platform, 0 };
    cl_context ctx = p_clCreateContext(props, 1, &device, NULL, NULL, &err);
    if (!ctx) { proto_error("context_creation_failed"); return; }

    cl_command_queue queue = p_clCreateCommandQueue(ctx, device, 0, &err);
    if (!queue) { proto_error("queue_creation_failed"); p_clReleaseContext(ctx); return; }

    cl_program program = p_clCreateProgramWithSource(ctx, 1, &kernel_source, NULL, &err);
    if (!program) { proto_error("program_creation_failed"); goto cleanup_queue; }

    err = p_clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        char log[8192];
        size_t log_len = 0;
        p_clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof(log) - 1, log, &log_len);
        log[log_len < sizeof(log) ? log_len : sizeof(log) - 1] = 0;
        printf("ERROR kernel_build_failed: %s\n", log);
        fflush(stdout);
        goto cleanup_program;
    }

    {
        cl_kernel kernel = p_clCreateKernel(program, "sha256_bruteforce", &err);
        if (!kernel) { proto_error("kernel_creation_failed"); goto cleanup_program; }

        cl_mem buf_charset = p_clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                               charset_len, (void*)charset, &err);
        cl_mem buf_target = p_clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                              sizeof(target_words), target_words, &err);
        cl_mem buf_found_flag = p_clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &err);
        cl_mem buf_found_index = p_clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_ulong), NULL, &err);

        if (!buf_charset || !buf_target || !buf_found_flag || !buf_found_index) {
            proto_error("buffer_creation_failed");
            goto cleanup_kernel;
        }

        p_clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_charset);
        p_clSetKernelArg(kernel, 1, sizeof(cl_uint), &charset_len);
        p_clSetKernelArg(kernel, 4, sizeof(cl_mem), &buf_target);
        p_clSetKernelArg(kernel, 5, sizeof(cl_mem), &buf_found_flag);
        p_clSetKernelArg(kernel, 6, sizeof(cl_mem), &buf_found_index);

        unsigned long long total_tried = 0;
        int found = 0;
        char found_str[64];

        for (uint32_t length = minlen; length <= maxlen && !found; length++) {
            uint64_t space = ipow((uint64_t)charset_len, length);
            uint64_t offset = 0;

            cl_uint zero = 0;
            p_clEnqueueWriteBuffer(queue, buf_found_flag, CL_TRUE, 0, sizeof(zero), &zero, 0, NULL, NULL);

            p_clSetKernelArg(kernel, 2, sizeof(cl_uint), &length);

            while (offset < space && !found) {
                uint64_t remaining = space - offset;
                uint64_t batch = remaining < BATCH_SIZE ? remaining : BATCH_SIZE;
                size_t global_size = (size_t)(((batch + LOCAL_SIZE - 1) / LOCAL_SIZE) * LOCAL_SIZE);
                size_t local_size = LOCAL_SIZE;

                cl_ulong base_offset = (cl_ulong)offset;
                p_clSetKernelArg(kernel, 3, sizeof(cl_ulong), &base_offset);

                err = p_clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL);
                if (err != CL_SUCCESS) { proto_error("kernel_dispatch_failed"); goto cleanup_buffers; }
                p_clFinish(queue);

                cl_uint flag = 0;
                p_clEnqueueReadBuffer(queue, buf_found_flag, CL_TRUE, 0, sizeof(flag), &flag, 0, NULL, NULL);

                offset += batch;
                total_tried += batch;

                if (flag) {
                    cl_ulong found_idx = 0;
                    p_clEnqueueReadBuffer(queue, buf_found_index, CL_TRUE, 0, sizeof(found_idx), &found_idx, 0, NULL, NULL);
                    decode_candidate((uint64_t)found_idx, charset, charset_len, length, found_str);
                    found = 1;
                    break;
                }

                proto_progress(total_tried);
            }
        }

        if (found) {
            proto_found(found_str);
        } else {
            proto_done(total_tried);
        }

cleanup_buffers:
        if (buf_charset) p_clReleaseMemObject(buf_charset);
        if (buf_target) p_clReleaseMemObject(buf_target);
        if (buf_found_flag) p_clReleaseMemObject(buf_found_flag);
        if (buf_found_index) p_clReleaseMemObject(buf_found_index);
cleanup_kernel:
        p_clReleaseKernel(kernel);
    }

cleanup_program:
    p_clReleaseProgram(program);
cleanup_queue:
    p_clReleaseCommandQueue(queue);
    p_clReleaseContext(ctx);
}

/* ===================== entry point ==================================== */

int main(int argc, char** argv) {
    if (argc < 2) {
        proto_error("usage: checker_gpu.exe list | checker_gpu.exe brute <hash> <charset> <min> <max> <device_index>");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        if (!load_opencl()) { proto_error("opencl_not_found"); return 1; }
        list_devices();
        return 0;
    }

    if (strcmp(argv[1], "brute") == 0) {
        if (argc < 7) {
            proto_error("usage: checker_gpu.exe brute <hash> <charset> <min> <max> <device_index>");
            return 1;
        }
        const char* target_hex = argv[2];
        const char* charset = argv[3];
        uint32_t minlen = (uint32_t)atoi(argv[4]);
        uint32_t maxlen = (uint32_t)atoi(argv[5]);
        int device_index = atoi(argv[6]);
        brute_gpu(target_hex, charset, minlen, maxlen, device_index);
        return 0;
    }

    proto_error("unknown_command");
    return 1;
}

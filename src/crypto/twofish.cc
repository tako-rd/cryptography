/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "twofish.h"
#include "bit_utill.h"
#include "byte_utill.h"

namespace cryptography {

#define SUCCESS                       0
#define FAILURE                       1

#define TWOFISH_128BIT_KVALUE         2
#define TWOFISH_192BIT_KVALUE         3
#define TWOFISH_256BIT_KVALUE         4

#define TWOFISH_128BIT_KEY_BYTE_SIZE  16
#define TWOFISH_192BIT_KEY_BYTE_SIZE  24
#define TWOFISH_256BIT_KEY_BYTE_SIZE  32

#define TWOFISH_ROUND_MAX             15

#define TWOFISH_RHO                   0x0101'0101   /**< 2^24 + 2^16 + 2^8 + 2^0     */
#define MDS_MODULUS                   0x0000'0169   /**< 2^8 + 2^6 + 2^5 + 2^3 + 2^0 */
#define RS_MODULUS                    0x0000'014D   /**< 2^8 + 2^6 + 2^3 + 2^2 + 2^0 */

#define ROTR4(x, shift)               (uint8_t)((((x) >> (shift)) | ((x) << (4 - shift))) & 0x0F)

#define GF_MDS(x, z)                  gf_mult((x), (z), MDS_MODULUS)
#define GF_RS(x, z)                   gf_mult((x), (z), RS_MODULUS)

#if 0
static const uint8_t q0t0[16] = {
  0x08, 0x01, 0x07, 0x0D, 0x06, 0x0F, 0x03, 0x02, 0x00, 0x0B, 0x05, 0x09, 0x0E, 0x0C, 0x0A, 0x04
};

static const uint8_t q0t1[16] = {
  0x0E, 0x0C, 0x0B, 0x08, 0x01, 0x02, 0x03, 0x05, 0x0F, 0x04, 0x0A, 0x06, 0x07, 0x00, 0x09, 0x0D
};

static const uint8_t q0t2[16] = {
  0x0B, 0x0A, 0x05, 0x0E, 0x06, 0x0D, 0x09, 0x00, 0x0C, 0x08, 0x0F, 0x03, 0x02, 0x04, 0x07, 0x01
};

static const uint8_t q0t3[16] = {
  0x0D, 0x07, 0x0F, 0x04, 0x01, 0x02, 0x06, 0x0E, 0x09, 0x0B, 0x03, 0x00, 0x08, 0x05, 0x0C, 0x0A
};

static const uint8_t q1t0[16] = {
  0x02, 0x08, 0x0B, 0x0D, 0x0F, 0x07, 0x06, 0x0E, 0x03, 0x01, 0x09, 0x04, 0x00, 0x0A, 0x0C, 0x05
};

static const uint8_t q1t1[16] = {
  0x01, 0x0E, 0x02, 0x0B, 0x04, 0x0C, 0x03, 0x07, 0x06, 0x0D, 0x0A, 0x05, 0x0F, 0x09, 0x00, 0x08
};

static const uint8_t q1t2[16] = {
  0x04, 0x0C, 0x07, 0x05, 0x01, 0x06, 0x09, 0x0A, 0x00, 0x0E, 0x0D, 0x08, 0x02, 0x0B, 0x03, 0x0F
};

static const uint8_t q1t3[16] = {
  0x0B, 0x09, 0x05, 0x01, 0x0C, 0x03, 0x0D, 0x0E, 0x06, 0x04, 0x07, 0x0F, 0x02, 0x00, 0x08, 0x0A
};
#endif

static const uint32_t mds_col0[256] = {
  0x00000000, 0xefef5b01, 0xb7b7b602, 0x5858ed03,
  0x07070504, 0xe8e85e05, 0xb0b0b306, 0x5f5fe807,
  0x0e0e0a08, 0xe1e15109, 0xb9b9bc0a, 0x5656e70b,
  0x09090f0c, 0xe6e6540d, 0xbebeb90e, 0x5151e20f,
  0x1c1c1410, 0xf3f34f11, 0xababa212, 0x4444f913,
  0x1b1b1114, 0xf4f44a15, 0xacaca716, 0x4343fc17,
  0x12121e18, 0xfdfd4519, 0xa5a5a81a, 0x4a4af31b,
  0x15151b1c, 0xfafa401d, 0xa2a2ad1e, 0x4d4df61f,
  0x38382820, 0xd7d77321, 0x8f8f9e22, 0x6060c523,
  0x3f3f2d24, 0xd0d07625, 0x88889b26, 0x6767c027,
  0x36362228, 0xd9d97929, 0x8181942a, 0x6e6ecf2b,
  0x3131272c, 0xdede7c2d, 0x8686912e, 0x6969ca2f,
  0x24243c30, 0xcbcb6731, 0x93938a32, 0x7c7cd133,
  0x23233934, 0xcccc6235, 0x94948f36, 0x7b7bd437,
  0x2a2a3638, 0xc5c56d39, 0x9d9d803a, 0x7272db3b,
  0x2d2d333c, 0xc2c2683d, 0x9a9a853e, 0x7575de3f,
  0x70705040, 0x9f9f0b41, 0xc7c7e642, 0x2828bd43,
  0x77775544, 0x98980e45, 0xc0c0e346, 0x2f2fb847,
  0x7e7e5a48, 0x91910149, 0xc9c9ec4a, 0x2626b74b,
  0x79795f4c, 0x9696044d, 0xcecee94e, 0x2121b24f,
  0x6c6c4450, 0x83831f51, 0xdbdbf252, 0x3434a953,
  0x6b6b4154, 0x84841a55, 0xdcdcf756, 0x3333ac57,
  0x62624e58, 0x8d8d1559, 0xd5d5f85a, 0x3a3aa35b,
  0x65654b5c, 0x8a8a105d, 0xd2d2fd5e, 0x3d3da65f,
  0x48487860, 0xa7a72361, 0xffffce62, 0x10109563,
  0x4f4f7d64, 0xa0a02665, 0xf8f8cb66, 0x17179067,
  0x46467268, 0xa9a92969, 0xf1f1c46a, 0x1e1e9f6b,
  0x4141776c, 0xaeae2c6d, 0xf6f6c16e, 0x19199a6f,
  0x54546c70, 0xbbbb3771, 0xe3e3da72, 0x0c0c8173,
  0x53536974, 0xbcbc3275, 0xe4e4df76, 0x0b0b8477,
  0x5a5a6678, 0xb5b53d79, 0xededd07a, 0x02028b7b,
  0x5d5d637c, 0xb2b2387d, 0xeaead57e, 0x05058e7f,
  0xe0e0a080, 0x0f0ffb81, 0x57571682, 0xb8b84d83,
  0xe7e7a584, 0x0808fe85, 0x50501386, 0xbfbf4887,
  0xeeeeaa88, 0x0101f189, 0x59591c8a, 0xb6b6478b,
  0xe9e9af8c, 0x0606f48d, 0x5e5e198e, 0xb1b1428f,
  0xfcfcb490, 0x1313ef91, 0x4b4b0292, 0xa4a45993,
  0xfbfbb194, 0x1414ea95, 0x4c4c0796, 0xa3a35c97,
  0xf2f2be98, 0x1d1de599, 0x4545089a, 0xaaaa539b,
  0xf5f5bb9c, 0x1a1ae09d, 0x42420d9e, 0xadad569f,
  0xd8d888a0, 0x3737d3a1, 0x6f6f3ea2, 0x808065a3,
  0xdfdf8da4, 0x3030d6a5, 0x68683ba6, 0x878760a7,
  0xd6d682a8, 0x3939d9a9, 0x616134aa, 0x8e8e6fab,
  0xd1d187ac, 0x3e3edcad, 0x666631ae, 0x89896aaf,
  0xc4c49cb0, 0x2b2bc7b1, 0x73732ab2, 0x9c9c71b3,
  0xc3c399b4, 0x2c2cc2b5, 0x74742fb6, 0x9b9b74b7,
  0xcaca96b8, 0x2525cdb9, 0x7d7d20ba, 0x92927bbb,
  0xcdcd93bc, 0x2222c8bd, 0x7a7a25be, 0x95957ebf,
  0x9090f0c0, 0x7f7fabc1, 0x272746c2, 0xc8c81dc3,
  0x9797f5c4, 0x7878aec5, 0x202043c6, 0xcfcf18c7,
  0x9e9efac8, 0x7171a1c9, 0x29294cca, 0xc6c617cb,
  0x9999ffcc, 0x7676a4cd, 0x2e2e49ce, 0xc1c112cf,
  0x8c8ce4d0, 0x6363bfd1, 0x3b3b52d2, 0xd4d409d3,
  0x8b8be1d4, 0x6464bad5, 0x3c3c57d6, 0xd3d30cd7,
  0x8282eed8, 0x6d6db5d9, 0x353558da, 0xdada03db,
  0x8585ebdc, 0x6a6ab0dd, 0x32325dde, 0xdddd06df,
  0xa8a8d8e0, 0x474783e1, 0x1f1f6ee2, 0xf0f035e3,
  0xafafdde4, 0x404086e5, 0x18186be6, 0xf7f730e7,
  0xa6a6d2e8, 0x494989e9, 0x111164ea, 0xfefe3feb,
  0xa1a1d7ec, 0x4e4e8ced, 0x161661ee, 0xf9f93aef,
  0xb4b4ccf0, 0x5b5b97f1, 0x03037af2, 0xecec21f3,
  0xb3b3c9f4, 0x5c5c92f5, 0x04047ff6, 0xebeb24f7,
  0xbabac6f8, 0x55559df9, 0x0d0d70fa, 0xe2e22bfb,
  0xbdbdc3fc, 0x525298fd, 0x0a0a75fe, 0xe5e52eff,
};

static const uint32_t mds_col1[256] = {
  0x00000000, 0x015befef, 0x02b6b7b7, 0x03ed5858,
  0x04050707, 0x055ee8e8, 0x06b3b0b0, 0x07e85f5f,
  0x080a0e0e, 0x0951e1e1, 0x0abcb9b9, 0x0be75656,
  0x0c0f0909, 0x0d54e6e6, 0x0eb9bebe, 0x0fe25151,
  0x10141c1c, 0x114ff3f3, 0x12a2abab, 0x13f94444,
  0x14111b1b, 0x154af4f4, 0x16a7acac, 0x17fc4343,
  0x181e1212, 0x1945fdfd, 0x1aa8a5a5, 0x1bf34a4a,
  0x1c1b1515, 0x1d40fafa, 0x1eada2a2, 0x1ff64d4d,
  0x20283838, 0x2173d7d7, 0x229e8f8f, 0x23c56060,
  0x242d3f3f, 0x2576d0d0, 0x269b8888, 0x27c06767,
  0x28223636, 0x2979d9d9, 0x2a948181, 0x2bcf6e6e,
  0x2c273131, 0x2d7cdede, 0x2e918686, 0x2fca6969,
  0x303c2424, 0x3167cbcb, 0x328a9393, 0x33d17c7c,
  0x34392323, 0x3562cccc, 0x368f9494, 0x37d47b7b,
  0x38362a2a, 0x396dc5c5, 0x3a809d9d, 0x3bdb7272,
  0x3c332d2d, 0x3d68c2c2, 0x3e859a9a, 0x3fde7575,
  0x40507070, 0x410b9f9f, 0x42e6c7c7, 0x43bd2828,
  0x44557777, 0x450e9898, 0x46e3c0c0, 0x47b82f2f,
  0x485a7e7e, 0x49019191, 0x4aecc9c9, 0x4bb72626,
  0x4c5f7979, 0x4d049696, 0x4ee9cece, 0x4fb22121,
  0x50446c6c, 0x511f8383, 0x52f2dbdb, 0x53a93434,
  0x54416b6b, 0x551a8484, 0x56f7dcdc, 0x57ac3333,
  0x584e6262, 0x59158d8d, 0x5af8d5d5, 0x5ba33a3a,
  0x5c4b6565, 0x5d108a8a, 0x5efdd2d2, 0x5fa63d3d,
  0x60784848, 0x6123a7a7, 0x62ceffff, 0x63951010,
  0x647d4f4f, 0x6526a0a0, 0x66cbf8f8, 0x67901717,
  0x68724646, 0x6929a9a9, 0x6ac4f1f1, 0x6b9f1e1e,
  0x6c774141, 0x6d2caeae, 0x6ec1f6f6, 0x6f9a1919,
  0x706c5454, 0x7137bbbb, 0x72dae3e3, 0x73810c0c,
  0x74695353, 0x7532bcbc, 0x76dfe4e4, 0x77840b0b,
  0x78665a5a, 0x793db5b5, 0x7ad0eded, 0x7b8b0202,
  0x7c635d5d, 0x7d38b2b2, 0x7ed5eaea, 0x7f8e0505,
  0x80a0e0e0, 0x81fb0f0f, 0x82165757, 0x834db8b8,
  0x84a5e7e7, 0x85fe0808, 0x86135050, 0x8748bfbf,
  0x88aaeeee, 0x89f10101, 0x8a1c5959, 0x8b47b6b6,
  0x8cafe9e9, 0x8df40606, 0x8e195e5e, 0x8f42b1b1,
  0x90b4fcfc, 0x91ef1313, 0x92024b4b, 0x9359a4a4,
  0x94b1fbfb, 0x95ea1414, 0x96074c4c, 0x975ca3a3,
  0x98bef2f2, 0x99e51d1d, 0x9a084545, 0x9b53aaaa,
  0x9cbbf5f5, 0x9de01a1a, 0x9e0d4242, 0x9f56adad,
  0xa088d8d8, 0xa1d33737, 0xa23e6f6f, 0xa3658080,
  0xa48ddfdf, 0xa5d63030, 0xa63b6868, 0xa7608787,
  0xa882d6d6, 0xa9d93939, 0xaa346161, 0xab6f8e8e,
  0xac87d1d1, 0xaddc3e3e, 0xae316666, 0xaf6a8989,
  0xb09cc4c4, 0xb1c72b2b, 0xb22a7373, 0xb3719c9c,
  0xb499c3c3, 0xb5c22c2c, 0xb62f7474, 0xb7749b9b,
  0xb896caca, 0xb9cd2525, 0xba207d7d, 0xbb7b9292,
  0xbc93cdcd, 0xbdc82222, 0xbe257a7a, 0xbf7e9595,
  0xc0f09090, 0xc1ab7f7f, 0xc2462727, 0xc31dc8c8,
  0xc4f59797, 0xc5ae7878, 0xc6432020, 0xc718cfcf,
  0xc8fa9e9e, 0xc9a17171, 0xca4c2929, 0xcb17c6c6,
  0xccff9999, 0xcda47676, 0xce492e2e, 0xcf12c1c1,
  0xd0e48c8c, 0xd1bf6363, 0xd2523b3b, 0xd309d4d4,
  0xd4e18b8b, 0xd5ba6464, 0xd6573c3c, 0xd70cd3d3,
  0xd8ee8282, 0xd9b56d6d, 0xda583535, 0xdb03dada,
  0xdceb8585, 0xddb06a6a, 0xde5d3232, 0xdf06dddd,
  0xe0d8a8a8, 0xe1834747, 0xe26e1f1f, 0xe335f0f0,
  0xe4ddafaf, 0xe5864040, 0xe66b1818, 0xe730f7f7,
  0xe8d2a6a6, 0xe9894949, 0xea641111, 0xeb3ffefe,
  0xecd7a1a1, 0xed8c4e4e, 0xee611616, 0xef3af9f9,
  0xf0ccb4b4, 0xf1975b5b, 0xf27a0303, 0xf321ecec,
  0xf4c9b3b3, 0xf5925c5c, 0xf67f0404, 0xf724ebeb,
  0xf8c6baba, 0xf99d5555, 0xfa700d0d, 0xfb2be2e2,
  0xfcc3bdbd, 0xfd985252, 0xfe750a0a, 0xff2ee5e5,
};

static const uint32_t mds_col2[256] = {
  0x00000000, 0xef01ef5b, 0xb702b7b6, 0x580358ed,
  0x07040705, 0xe805e85e, 0xb006b0b3, 0x5f075fe8,
  0x0e080e0a, 0xe109e151, 0xb90ab9bc, 0x560b56e7,
  0x090c090f, 0xe60de654, 0xbe0ebeb9, 0x510f51e2,
  0x1c101c14, 0xf311f34f, 0xab12aba2, 0x441344f9,
  0x1b141b11, 0xf415f44a, 0xac16aca7, 0x431743fc,
  0x1218121e, 0xfd19fd45, 0xa51aa5a8, 0x4a1b4af3,
  0x151c151b, 0xfa1dfa40, 0xa21ea2ad, 0x4d1f4df6,
  0x38203828, 0xd721d773, 0x8f228f9e, 0x602360c5,
  0x3f243f2d, 0xd025d076, 0x8826889b, 0x672767c0,
  0x36283622, 0xd929d979, 0x812a8194, 0x6e2b6ecf,
  0x312c3127, 0xde2dde7c, 0x862e8691, 0x692f69ca,
  0x2430243c, 0xcb31cb67, 0x9332938a, 0x7c337cd1,
  0x23342339, 0xcc35cc62, 0x9436948f, 0x7b377bd4,
  0x2a382a36, 0xc539c56d, 0x9d3a9d80, 0x723b72db,
  0x2d3c2d33, 0xc23dc268, 0x9a3e9a85, 0x753f75de,
  0x70407050, 0x9f419f0b, 0xc742c7e6, 0x284328bd,
  0x77447755, 0x9845980e, 0xc046c0e3, 0x2f472fb8,
  0x7e487e5a, 0x91499101, 0xc94ac9ec, 0x264b26b7,
  0x794c795f, 0x964d9604, 0xce4ecee9, 0x214f21b2,
  0x6c506c44, 0x8351831f, 0xdb52dbf2, 0x345334a9,
  0x6b546b41, 0x8455841a, 0xdc56dcf7, 0x335733ac,
  0x6258624e, 0x8d598d15, 0xd55ad5f8, 0x3a5b3aa3,
  0x655c654b, 0x8a5d8a10, 0xd25ed2fd, 0x3d5f3da6,
  0x48604878, 0xa761a723, 0xff62ffce, 0x10631095,
  0x4f644f7d, 0xa065a026, 0xf866f8cb, 0x17671790,
  0x46684672, 0xa969a929, 0xf16af1c4, 0x1e6b1e9f,
  0x416c4177, 0xae6dae2c, 0xf66ef6c1, 0x196f199a,
  0x5470546c, 0xbb71bb37, 0xe372e3da, 0x0c730c81,
  0x53745369, 0xbc75bc32, 0xe476e4df, 0x0b770b84,
  0x5a785a66, 0xb579b53d, 0xed7aedd0, 0x027b028b,
  0x5d7c5d63, 0xb27db238, 0xea7eead5, 0x057f058e,
  0xe080e0a0, 0x0f810ffb, 0x57825716, 0xb883b84d,
  0xe784e7a5, 0x088508fe, 0x50865013, 0xbf87bf48,
  0xee88eeaa, 0x018901f1, 0x598a591c, 0xb68bb647,
  0xe98ce9af, 0x068d06f4, 0x5e8e5e19, 0xb18fb142,
  0xfc90fcb4, 0x139113ef, 0x4b924b02, 0xa493a459,
  0xfb94fbb1, 0x149514ea, 0x4c964c07, 0xa397a35c,
  0xf298f2be, 0x1d991de5, 0x459a4508, 0xaa9baa53,
  0xf59cf5bb, 0x1a9d1ae0, 0x429e420d, 0xad9fad56,
  0xd8a0d888, 0x37a137d3, 0x6fa26f3e, 0x80a38065,
  0xdfa4df8d, 0x30a530d6, 0x68a6683b, 0x87a78760,
  0xd6a8d682, 0x39a939d9, 0x61aa6134, 0x8eab8e6f,
  0xd1acd187, 0x3ead3edc, 0x66ae6631, 0x89af896a,
  0xc4b0c49c, 0x2bb12bc7, 0x73b2732a, 0x9cb39c71,
  0xc3b4c399, 0x2cb52cc2, 0x74b6742f, 0x9bb79b74,
  0xcab8ca96, 0x25b925cd, 0x7dba7d20, 0x92bb927b,
  0xcdbccd93, 0x22bd22c8, 0x7abe7a25, 0x95bf957e,
  0x90c090f0, 0x7fc17fab, 0x27c22746, 0xc8c3c81d,
  0x97c497f5, 0x78c578ae, 0x20c62043, 0xcfc7cf18,
  0x9ec89efa, 0x71c971a1, 0x29ca294c, 0xc6cbc617,
  0x99cc99ff, 0x76cd76a4, 0x2ece2e49, 0xc1cfc112,
  0x8cd08ce4, 0x63d163bf, 0x3bd23b52, 0xd4d3d409,
  0x8bd48be1, 0x64d564ba, 0x3cd63c57, 0xd3d7d30c,
  0x82d882ee, 0x6dd96db5, 0x35da3558, 0xdadbda03,
  0x85dc85eb, 0x6add6ab0, 0x32de325d, 0xdddfdd06,
  0xa8e0a8d8, 0x47e14783, 0x1fe21f6e, 0xf0e3f035,
  0xafe4afdd, 0x40e54086, 0x18e6186b, 0xf7e7f730,
  0xa6e8a6d2, 0x49e94989, 0x11ea1164, 0xfeebfe3f,
  0xa1eca1d7, 0x4eed4e8c, 0x16ee1661, 0xf9eff93a,
  0xb4f0b4cc, 0x5bf15b97, 0x03f2037a, 0xecf3ec21,
  0xb3f4b3c9, 0x5cf55c92, 0x04f6047f, 0xebf7eb24,
  0xbaf8bac6, 0x55f9559d, 0x0dfa0d70, 0xe2fbe22b,
  0xbdfcbdc3, 0x52fd5298, 0x0afe0a75, 0xe5ffe52e,
};

static const uint32_t mds_col3[256] = {
  0x00000000, 0x5bef015b, 0xb6b702b6, 0xed5803ed,
  0x05070405, 0x5ee8055e, 0xb3b006b3, 0xe85f07e8,
  0x0a0e080a, 0x51e10951, 0xbcb90abc, 0xe7560be7,
  0x0f090c0f, 0x54e60d54, 0xb9be0eb9, 0xe2510fe2,
  0x141c1014, 0x4ff3114f, 0xa2ab12a2, 0xf94413f9,
  0x111b1411, 0x4af4154a, 0xa7ac16a7, 0xfc4317fc,
  0x1e12181e, 0x45fd1945, 0xa8a51aa8, 0xf34a1bf3,
  0x1b151c1b, 0x40fa1d40, 0xada21ead, 0xf64d1ff6,
  0x28382028, 0x73d72173, 0x9e8f229e, 0xc56023c5,
  0x2d3f242d, 0x76d02576, 0x9b88269b, 0xc06727c0,
  0x22362822, 0x79d92979, 0x94812a94, 0xcf6e2bcf,
  0x27312c27, 0x7cde2d7c, 0x91862e91, 0xca692fca,
  0x3c24303c, 0x67cb3167, 0x8a93328a, 0xd17c33d1,
  0x39233439, 0x62cc3562, 0x8f94368f, 0xd47b37d4,
  0x362a3836, 0x6dc5396d, 0x809d3a80, 0xdb723bdb,
  0x332d3c33, 0x68c23d68, 0x859a3e85, 0xde753fde,
  0x50704050, 0x0b9f410b, 0xe6c742e6, 0xbd2843bd,
  0x55774455, 0x0e98450e, 0xe3c046e3, 0xb82f47b8,
  0x5a7e485a, 0x01914901, 0xecc94aec, 0xb7264bb7,
  0x5f794c5f, 0x04964d04, 0xe9ce4ee9, 0xb2214fb2,
  0x446c5044, 0x1f83511f, 0xf2db52f2, 0xa93453a9,
  0x416b5441, 0x1a84551a, 0xf7dc56f7, 0xac3357ac,
  0x4e62584e, 0x158d5915, 0xf8d55af8, 0xa33a5ba3,
  0x4b655c4b, 0x108a5d10, 0xfdd25efd, 0xa63d5fa6,
  0x78486078, 0x23a76123, 0xceff62ce, 0x95106395,
  0x7d4f647d, 0x26a06526, 0xcbf866cb, 0x90176790,
  0x72466872, 0x29a96929, 0xc4f16ac4, 0x9f1e6b9f,
  0x77416c77, 0x2cae6d2c, 0xc1f66ec1, 0x9a196f9a,
  0x6c54706c, 0x37bb7137, 0xdae372da, 0x810c7381,
  0x69537469, 0x32bc7532, 0xdfe476df, 0x840b7784,
  0x665a7866, 0x3db5793d, 0xd0ed7ad0, 0x8b027b8b,
  0x635d7c63, 0x38b27d38, 0xd5ea7ed5, 0x8e057f8e,
  0xa0e080a0, 0xfb0f81fb, 0x16578216, 0x4db8834d,
  0xa5e784a5, 0xfe0885fe, 0x13508613, 0x48bf8748,
  0xaaee88aa, 0xf10189f1, 0x1c598a1c, 0x47b68b47,
  0xafe98caf, 0xf4068df4, 0x195e8e19, 0x42b18f42,
  0xb4fc90b4, 0xef1391ef, 0x024b9202, 0x59a49359,
  0xb1fb94b1, 0xea1495ea, 0x074c9607, 0x5ca3975c,
  0xbef298be, 0xe51d99e5, 0x08459a08, 0x53aa9b53,
  0xbbf59cbb, 0xe01a9de0, 0x0d429e0d, 0x56ad9f56,
  0x88d8a088, 0xd337a1d3, 0x3e6fa23e, 0x6580a365,
  0x8ddfa48d, 0xd630a5d6, 0x3b68a63b, 0x6087a760,
  0x82d6a882, 0xd939a9d9, 0x3461aa34, 0x6f8eab6f,
  0x87d1ac87, 0xdc3eaddc, 0x3166ae31, 0x6a89af6a,
  0x9cc4b09c, 0xc72bb1c7, 0x2a73b22a, 0x719cb371,
  0x99c3b499, 0xc22cb5c2, 0x2f74b62f, 0x749bb774,
  0x96cab896, 0xcd25b9cd, 0x207dba20, 0x7b92bb7b,
  0x93cdbc93, 0xc822bdc8, 0x257abe25, 0x7e95bf7e,
  0xf090c0f0, 0xab7fc1ab, 0x4627c246, 0x1dc8c31d,
  0xf597c4f5, 0xae78c5ae, 0x4320c643, 0x18cfc718,
  0xfa9ec8fa, 0xa171c9a1, 0x4c29ca4c, 0x17c6cb17,
  0xff99ccff, 0xa476cda4, 0x492ece49, 0x12c1cf12,
  0xe48cd0e4, 0xbf63d1bf, 0x523bd252, 0x09d4d309,
  0xe18bd4e1, 0xba64d5ba, 0x573cd657, 0x0cd3d70c,
  0xee82d8ee, 0xb56dd9b5, 0x5835da58, 0x03dadb03,
  0xeb85dceb, 0xb06addb0, 0x5d32de5d, 0x06dddf06,
  0xd8a8e0d8, 0x8347e183, 0x6e1fe26e, 0x35f0e335,
  0xddafe4dd, 0x8640e586, 0x6b18e66b, 0x30f7e730,
  0xd2a6e8d2, 0x8949e989, 0x6411ea64, 0x3ffeeb3f,
  0xd7a1ecd7, 0x8c4eed8c, 0x6116ee61, 0x3af9ef3a,
  0xccb4f0cc, 0x975bf197, 0x7a03f27a, 0x21ecf321,
  0xc9b3f4c9, 0x925cf592, 0x7f04f67f, 0x24ebf724,
  0xc6baf8c6, 0x9d55f99d, 0x700dfa70, 0x2be2fb2b,
  0xc3bdfcc3, 0x9852fd98, 0x750afe75, 0x2ee5ff2e,
};

static const uint8_t q0[256] = {
  0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76,
  0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
  0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
  0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
  0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23,
  0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
  0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c,
  0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
  0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
  0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
  0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66,
  0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
  0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba,
  0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
  0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
  0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
  0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2,
  0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
  0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab,
  0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
  0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
  0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
  0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a,
  0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
  0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02,
  0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
  0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
  0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
  0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8,
  0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
  0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00,
  0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
};

static const uint8_t q1[256] = {
  0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8,
  0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
  0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
  0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
  0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d,
  0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
  0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3,
  0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
  0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
  0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
  0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70,
  0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
  0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc,
  0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
  0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
  0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
  0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3,
  0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
  0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49,
  0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
  0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
  0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
  0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19,
  0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
  0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5,
  0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
  0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
  0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
  0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab,
  0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
  0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2,
  0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
};

int32_t twofish::initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept {
  uint32_t k[8] = {0};

  enable_intrinsic_func_ = enable_intrinsic;

  switch (ksize) {
    case TWOFISH_128BIT_KEY_BYTE_SIZE:
      k_ = TWOFISH_128BIT_KVALUE;
      has_subkeys_ = true;
      LITTLEENDIAN_32BIT_U8_TO_U128_COPY(key, k);
      expand_key(k, subkey_);
      memset(k, 0xCC, sizeof(k));
      break;
    case TWOFISH_192BIT_KEY_BYTE_SIZE:
      k_ = TWOFISH_192BIT_KVALUE;
      has_subkeys_ = true;
      LITTLEENDIAN_32BIT_U8_TO_U128_COPY(key, k);
      expand_key(k, subkey_);
      memset(k, 0xCC, sizeof(k));
      break;
    case TWOFISH_256BIT_KEY_BYTE_SIZE:
      k_ = TWOFISH_256BIT_KVALUE;
      has_subkeys_ = true;
      LITTLEENDIAN_32BIT_U8_TO_U128_COPY(key, k);
      expand_key(k, subkey_);
      memset(k, 0xCC, sizeof(k));
      break;
    default:
      return FAILURE;
  }
  return SUCCESS;
}

int32_t twofish::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_encrypt(ptext, ctext);
  } else {
    no_intrinsic_encrypt(ptext, ctext);
  }
  return SUCCESS;
}

int32_t twofish::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_decrypt(ctext, ptext);
  } else {
    no_intrinsic_decrypt(ctext, ptext);
  }
  return SUCCESS;
}

void twofish::clear() noexcept {
  memset(mds_sbox0_, 0xCC, sizeof(mds_sbox0_));
  memset(mds_sbox1_, 0xCC, sizeof(mds_sbox1_));
  memset(mds_sbox2_, 0xCC, sizeof(mds_sbox2_));
  memset(mds_sbox3_, 0xCC, sizeof(mds_sbox3_));
  memset(subkey_, 0xCC, sizeof(subkey_));
  has_subkeys_ = false;
  enable_intrinsic_func_ = false;
}

inline void twofish::no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {
  uint32_t tmpp[4] = {0};
  uint32_t out[4] = {0};
  uint32_t f[2] = {0};

  LITTLEENDIAN_32BIT_U8_TO_U128_COPY(ptext, tmpp);

  tmpp[0] ^= subkey_[0];
  tmpp[1] ^= subkey_[1];
  tmpp[2] ^= subkey_[2];
  tmpp[3] ^= subkey_[3];

  for (int32_t i = 0; i <= TWOFISH_ROUND_MAX; i += 2) {
    f_function(tmpp[0], tmpp[1], i, f);
    tmpp[2] = ROTATE_RIGHT32((tmpp[2] ^ f[0]), 1);
    tmpp[3] = ROTATE_LEFT32(tmpp[3], 1) ^ f[1];

    f_function(tmpp[2], tmpp[3], i + 1, f);
    tmpp[0] = ROTATE_RIGHT32((tmpp[0] ^ f[0]), 1);
    tmpp[1] = ROTATE_LEFT32(tmpp[1], 1) ^ f[1];
  }

  out[0] ^= tmpp[2] ^ subkey_[4];
  out[1] ^= tmpp[3] ^ subkey_[5];
  out[2] ^= tmpp[0] ^ subkey_[6];
  out[3] ^= tmpp[1] ^ subkey_[7];

  LITTLEENDIAN_32BIT_U128_TO_U8_COPY(out, ctext);
}

inline void twofish::no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {
  uint32_t tmpc[4] = {0};
  uint32_t out[4] = {0};
  uint32_t f[2] = {0};

  LITTLEENDIAN_32BIT_U8_TO_U128_COPY(ctext, tmpc);

  tmpc[0] ^= subkey_[4];
  tmpc[1] ^= subkey_[5];
  tmpc[2] ^= subkey_[6];
  tmpc[3] ^= subkey_[7];

  for (int32_t i = TWOFISH_ROUND_MAX; i >= 0; i -= 2) {
    f_function(tmpc[0], tmpc[1], i, f);
    tmpc[2] = ROTATE_LEFT32(tmpc[2], 1) ^ f[0];
    tmpc[3] = ROTATE_RIGHT32((tmpc[3] ^ f[1]), 1);

    f_function(tmpc[2], tmpc[3], i - 1, f);
    tmpc[0] = ROTATE_LEFT32(tmpc[0], 1) ^ f[0];
    tmpc[1] = ROTATE_RIGHT32((tmpc[1] ^ f[1]), 1);
  }

  out[0] = tmpc[2] ^ subkey_[0];
  out[1] = tmpc[3] ^ subkey_[1];
  out[2] = tmpc[0] ^ subkey_[2];
  out[3] = tmpc[1] ^ subkey_[3];

  LITTLEENDIAN_32BIT_U128_TO_U8_COPY(out, ptext);
}

inline void twofish::intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {

}

inline void twofish::intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {

}

inline void twofish::expand_key(const uint32_t * const key, uint32_t *skeys) noexcept {
  uint32_t me[4] = {0};
  uint32_t mo[4] = {0};
  uint32_t s[4] = {0};
  uint32_t a = 0;
  uint32_t b = 0;
  uint32_t tmpsbox = 0;
  uint8_t bk[32] = {0};

  LITTLEENDIAN_32BIT_U256_TO_U8_COPY(key, bk);
#if 0
  for (uint32_t i = 0; i < 256; ++i) {
    q0_[i] = fix_q((uint8_t)i, q0t0, q0t1, q0t2, q0t3);
    q1_[i] = fix_q((uint8_t)i, q1t0, q1t1, q1t2, q1t3);
  }
#endif
  for (int32_t i = 0; i < k_; ++i) {
    me[i] = key[2 * i];
    mo[i] = key[2 * i + 1];

    s[(k_ - 1) - i] |= (GF_RS(0x01, bk[8 * i]) ^ 
                        GF_RS(0xA4, bk[8 * i + 1]) ^ 
                        GF_RS(0x55, bk[8 * i + 2]) ^ 
                        GF_RS(0x87, bk[8 * i + 3]) ^ 
                        GF_RS(0x5A, bk[8 * i + 4]) ^ 
                        GF_RS(0x58, bk[8 * i + 5]) ^ 
                        GF_RS(0xDB, bk[8 * i + 6]) ^ 
                        GF_RS(0x9E, bk[8 * i + 7])) <<  0;
    s[(k_ - 1) - i] |= (GF_RS(0xA4, bk[8 * i]) ^ 
                        GF_RS(0x56, bk[8 * i + 1]) ^ 
                        GF_RS(0x82, bk[8 * i + 2]) ^ 
                        GF_RS(0xF3, bk[8 * i + 3]) ^ 
                        GF_RS(0x1E, bk[8 * i + 4]) ^ 
                        GF_RS(0xC6, bk[8 * i + 5]) ^ 
                        GF_RS(0x68, bk[8 * i + 6]) ^ 
                        GF_RS(0xE5, bk[8 * i + 7])) <<  8;
    s[(k_ - 1) - i] |= (GF_RS(0x02, bk[8 * i]) ^ 
                        GF_RS(0xA1, bk[8 * i + 1]) ^ 
                        GF_RS(0xFC, bk[8 * i + 2]) ^ 
                        GF_RS(0xC1, bk[8 * i + 3]) ^ 
                        GF_RS(0x47, bk[8 * i + 4]) ^ 
                        GF_RS(0xAE, bk[8 * i + 5]) ^ 
                        GF_RS(0x3D, bk[8 * i + 6]) ^ 
                        GF_RS(0x19, bk[8 * i + 7])) << 16;
    s[(k_ - 1) - i] |= (GF_RS(0xA4, bk[8 * i]) ^ 
                        GF_RS(0x55, bk[8 * i + 1]) ^ 
                        GF_RS(0x87, bk[8 * i + 2]) ^ 
                        GF_RS(0x5A, bk[8 * i + 3]) ^ 
                        GF_RS(0x58, bk[8 * i + 4]) ^ 
                        GF_RS(0xDB, bk[8 * i + 5]) ^ 
                        GF_RS(0x9E, bk[8 * i + 6]) ^ 
                        GF_RS(0x03, bk[8 * i + 7])) << 24;
  }

  for (int32_t i = 0; i < 40; i += 2) {
    a = h_function(i * TWOFISH_RHO, me, k_);
    b = ROTATE_LEFT32(h_function((i + 1) * TWOFISH_RHO, mo, k_), 8);
    skeys[i] = (uint32_t)(a + b);
    skeys[i + 1] = ROTATE_LEFT32((uint32_t)(a + (b << 1)), 9);
  }

  fix_s(s, k_);
}

inline void twofish::f_function(uint32_t r0, uint32_t r1, int32_t round, uint32_t *f) const noexcept {
  uint32_t t0 = g_function(r0);
  uint32_t t1 = g_function(ROTATE_LEFT32(r1, 8));

  f[0] = (t0 + t1 + subkey_[2 * round + 8]);
  f[1] = (t0 + 2 * t1 + subkey_[2 * round + 9]);
}

inline uint32_t twofish::g_function(uint32_t x) const noexcept {
  uint8_t xi[4] = {0};

  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(x, xi);
  return mds_sbox0_[xi[0]] ^ mds_sbox1_[xi[1]] ^ mds_sbox2_[xi[2]] ^ mds_sbox3_[xi[3]];
}

inline uint32_t twofish::h_function(uint32_t x, uint32_t *l, uint32_t type) const noexcept {
  uint8_t by[4] = {0};
  uint8_t bl[4][4] = {0};

  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(x, by);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(l[0], bl[0]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(l[1], bl[1]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(l[2], bl[2]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(l[3], bl[3]);

  switch (type) {
    case 4:
      by[0] = q1[by[0]] ^ bl[3][0];
      by[1] = q0[by[1]] ^ bl[3][1];
      by[2] = q0[by[2]] ^ bl[3][2];
      by[3] = q1[by[3]] ^ bl[3][3];
    case 3:
      by[0] = q1[by[0]] ^ bl[2][0];
      by[1] = q1[by[1]] ^ bl[2][1];
      by[2] = q0[by[2]] ^ bl[2][2];
      by[3] = q0[by[3]] ^ bl[2][3];
    default:
      by[0] = q1[q0[q0[by[0]] ^ bl[1][0]] ^ bl[0][0]];
      by[1] = q0[q0[q1[by[1]] ^ bl[1][1]] ^ bl[0][1]];
      by[2] = q1[q1[q0[by[2]] ^ bl[1][2]] ^ bl[0][2]];
      by[3] = q0[q1[q1[by[3]] ^ bl[1][3]] ^ bl[0][3]];
      break;
  }
  return mds_col0[by[0]] ^ mds_col1[by[1]] ^ mds_col2[by[2]] ^ mds_col3[by[3]];
}

inline uint8_t twofish::gf_mult(uint8_t x, uint8_t y, uint32_t mod) const noexcept {
  uint8_t result = 0;
  uint8_t mask = 0x01;

  while (0x00 != mask) {
    if (0x00 != (y & mask)) {
      result ^= x;
    }
    x = (x << 1) ^ ((0x00 != (x & 0x80)) ? (uint8_t)mod : 0x00);
    mask <<= 1;
  }
  return result;
}
#if 0
inline uint8_t twofish::fix_q(uint8_t x, const uint8_t * const t0, const uint8_t * const t1, const uint8_t * const t2, const uint8_t * const t3) const noexcept {
  uint8_t a0 = 0;
  uint8_t a1 = 0;
  uint8_t b0 = 0;
  uint8_t b1 = 0;

  a0 = x >> 4;
  b0 = x % 16;

  a1 = a0 ^ b0;
  b1 = ((a0 ^ ROTR4(b0, 1)) ^ ((8 * a0)) % 16); 

  a0 = t0[a1];
  b0 = t1[b1];

  a1 = a0 ^ b0;
  b1 = ((a0 ^ ROTR4(b0, 1)) ^ ((8 * a0)) % 16); 

  a0 = t2[a1];
  b0 = t3[b1];

  return 16 * b0 + a0;
}
#endif
inline void twofish::fix_s(uint32_t *s, uint32_t type) noexcept {
  uint8_t bs[4][4] = {0};
  uint32_t z = 0;

  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(s[0], bs[0]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(s[1], bs[1]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(s[2], bs[2]);
  LITTLEENDIAN_32BIT_U32_TO_U8_COPY(s[3], bs[3]);

  switch (type) {
    case 4:
      for (uint32_t i = 0; i < 256; ++i) {
        mds_sbox0_[i] = mds_col0[q1[q0[q0[q1[q1[i] ^ bs[3][0]] ^ bs[2][0]] ^ bs[1][0]] ^ bs[0][0]]];
        mds_sbox1_[i] = mds_col1[q0[q0[q1[q1[q0[i] ^ bs[3][1]] ^ bs[2][1]] ^ bs[1][1]] ^ bs[0][1]]];
        mds_sbox2_[i] = mds_col2[q1[q1[q0[q0[q0[i] ^ bs[3][2]] ^ bs[2][2]] ^ bs[1][2]] ^ bs[0][2]]];
        mds_sbox3_[i] = mds_col3[q0[q1[q1[q0[q1[i] ^ bs[3][3]] ^ bs[2][3]] ^ bs[1][3]] ^ bs[0][3]]];
      }
      break;
    case 3:
      for (uint32_t i = 0; i < 256; ++i) {
        mds_sbox0_[i] = mds_col0[q1[q0[q0[q1[i] ^ bs[2][0]] ^ bs[1][0]] ^ bs[0][0]]];
        mds_sbox1_[i] = mds_col1[q0[q0[q1[q1[i] ^ bs[2][1]] ^ bs[1][1]] ^ bs[0][1]]];
        mds_sbox2_[i] = mds_col2[q1[q1[q0[q0[i] ^ bs[2][2]] ^ bs[1][2]] ^ bs[0][2]]];
        mds_sbox3_[i] = mds_col3[q0[q1[q1[q0[i] ^ bs[2][3]] ^ bs[1][3]] ^ bs[0][3]]];
      }
      break;
    case 2:
      for (uint32_t i = 0; i < 256; ++i) {
        mds_sbox0_[i] = mds_col0[q1[q0[q0[i] ^ bs[1][0]] ^ bs[0][0]]];
        mds_sbox1_[i] = mds_col1[q0[q0[q1[i] ^ bs[1][1]] ^ bs[0][1]]];
        mds_sbox2_[i] = mds_col2[q1[q1[q0[i] ^ bs[1][2]] ^ bs[0][2]]];
        mds_sbox3_[i] = mds_col3[q0[q1[q1[i] ^ bs[1][3]] ^ bs[0][3]]];
      }
      break;
    default:
      break;
  }
}

}

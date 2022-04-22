// uwords: count unique words on standard input
//
// Input is UTF-8-decoded and tokenized into words based on Unicode code
// character class. Control characters, space, and punctuation are not
// considered parts of words.
//
//   $ cc -O3 -o uwords uwords.c
//   $ ./uwords <essay.txt
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>     // int32_t, uint8_t
#include <stdio.h>      // fprintf, stdout, stderr
#include <stdlib.h>     // realloc, size_t
#include <string.h>     // memmove, memset, memcmp
#if _WIN32
#  include <windows.h>  // GetStdHandle, ReadFile, GetLastError, DWORD,
                        // HANDLE, ERROR_BROKEN_PIPE, STD_INPUT_HANDLE
#elif __unix__ || __APPLE__
#  include <unistd.h>   // read
#endif

// 64-bit FNV-style hash over a byte buffer.
static uint64_t
chunky64(const void *buf, size_t len, uint64_t key)
{
    size_t nblocks = len / 8;
    const unsigned char *p = buf;
    uint64_t h = 0x637f6e65916dff18 ^ key;

    for (size_t i = 0; i < nblocks; i++) {
        h ^= (uint64_t)p[0] <<  0 | (uint64_t)p[1] <<  8 |
             (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
             (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
             (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
        h *= 0xbf58476d1ce4e5b9;
        p += 8;
    }

    uint64_t last = len & 0xff;
    switch (len % 8) {
        case 7: last |= (uint64_t)p[6] << 56; // fallthrough
        case 6: last |= (uint64_t)p[5] << 48; // fallthrough
        case 5: last |= (uint64_t)p[4] << 40; // fallthrough
        case 4: last |= (uint64_t)p[3] << 32; // fallthrough
        case 3: last |= (uint64_t)p[2] << 24; // fallthrough
        case 2: last |= (uint64_t)p[1] << 16; // fallthrough
        case 1: last |= (uint64_t)p[0] <<  8;
                h ^= last;
                h *= 0xd6e8feb86659fd93;
    }

    h ^= h >> 32;
    return h ^ key;
}

// Return true if rune is a control character, space, or punctuation.
static int
should_skip(int32_t r)
{
    static const int32_t t[1<<13] = {
        [   0]=0x00000, [   3]=0x00001, [   7]=0x00002, [  11]=0x00003,
        [  12]=0x030fb, [  15]=0x00004, [  19]=0x00005, [  23]=0x00006,
        [  26]=0x00830, [  27]=0x00007, [  30]=0x00831, [  31]=0x00008,
        [  34]=0x00832, [  35]=0x00009, [  37]=0x00833, [  39]=0x0000a,
        [  41]=0x00834, [  43]=0x0000b, [  45]=0x00835, [  47]=0x0000c,
        [  49]=0x00836, [  50]=0x0000d, [  53]=0x00837, [  54]=0x0000e,
        [  57]=0x00838, [  58]=0x0000f, [  61]=0x00839, [  62]=0x00010,
        [  65]=0x0083a, [  66]=0x00011, [  69]=0x0083b, [  70]=0x00012,
        [  73]=0x0083c, [  74]=0x00013, [  77]=0x0083d, [  78]=0x00014,
        [  81]=0x0083e, [  82]=0x00015, [  86]=0x00016, [  90]=0x00017,
        [  94]=0x00018, [  98]=0x00019, [ 101]=0x0001a, [ 105]=0x0001b,
        [ 109]=0x0001c, [ 113]=0x0001d, [ 117]=0x0001e, [ 121]=0x0001f,
        [ 125]=0x00020, [ 129]=0x00021, [ 133]=0x00022, [ 137]=0x00023,
        [ 145]=0x00025, [ 148]=0x00026, [ 152]=0x00027, [ 156]=0x00028,
        [ 160]=0x00029, [ 164]=0x0002a, [ 172]=0x0002c, [ 176]=0x0002d,
        [ 180]=0x0002e, [ 184]=0x0002f, [ 206]=0x0085e, [ 227]=0x0003a,
        [ 231]=0x0003b, [ 240]=0x0fd3e, [ 244]=0x0fd3f, [ 247]=0x0003f,
        [ 250]=0x00040, [ 267]=0x115c1, [ 270]=0x1056f, [ 271]=0x115c2,
        [ 275]=0x115c3, [ 279]=0x115c4, [ 283]=0x115c5, [ 287]=0x115c6,
        [ 291]=0x115c7, [ 295]=0x115c8, [ 299]=0x115c9, [ 303]=0x115ca,
        [ 306]=0x115cb, [ 310]=0x115cc, [ 314]=0x115cd, [ 318]=0x115ce,
        [ 322]=0x115cf, [ 326]=0x115d0, [ 330]=0x115d1, [ 334]=0x115d2,
        [ 338]=0x115d3, [ 342]=0x115d4, [ 346]=0x115d5, [ 350]=0x115d6,
        [ 354]=0x115d7, [ 356]=0x0005b, [ 360]=0x0005c, [ 364]=0x0005d,
        [ 372]=0x0005f, [ 482]=0x0007b, [ 490]=0x0007d, [ 497]=0x0007f,
        [ 501]=0x00080, [ 505]=0x00081, [ 509]=0x00082, [ 513]=0x00083,
        [ 517]=0x00084, [ 521]=0x00085, [ 525]=0x00086, [ 529]=0x00087,
        [ 530]=0x0abeb, [ 533]=0x00088, [ 537]=0x00089, [ 541]=0x0008a,
        [ 545]=0x0008b, [ 548]=0x0008c, [ 552]=0x0008d, [ 556]=0x0008e,
        [ 560]=0x0008f, [ 564]=0x00090, [ 568]=0x00091, [ 572]=0x00092,
        [ 576]=0x00093, [ 580]=0x00094, [ 584]=0x00095, [ 588]=0x00096,
        [ 592]=0x00097, [ 595]=0x00098, [ 599]=0x00099, [ 603]=0x0009a,
        [ 607]=0x0009b, [ 611]=0x0009c, [ 615]=0x0009d, [ 619]=0x0009e,
        [ 622]=0x16fe2, [ 623]=0x0009f, [ 627]=0x000a0, [ 631]=0x000a1,
        [ 654]=0x000a7, [ 660]=0x010fb, [ 670]=0x000ab, [ 707]=0x02983,
        [ 711]=0x02984, [ 713]=0x000b6, [ 715]=0x02985, [ 717]=0x000b7,
        [ 719]=0x02986, [ 723]=0x02987, [ 727]=0x02988, [ 730]=0x02989,
        [ 733]=0x000bb, [ 734]=0x0298a, [ 738]=0x0298b, [ 742]=0x0298c,
        [ 746]=0x0298d, [ 748]=0x000bf, [ 750]=0x0298e, [ 754]=0x0298f,
        [ 758]=0x02990, [ 762]=0x02991, [ 766]=0x02992, [ 769]=0x11641,
        [ 770]=0x02993, [ 773]=0x11642, [ 774]=0x02994, [ 777]=0x11643,
        [ 778]=0x02995, [ 781]=0x02996, [ 784]=0x01944, [ 785]=0x02997,
        [ 788]=0x01945, [ 789]=0x02998, [ 891]=0x11660, [ 895]=0x11661,
        [ 899]=0x11662, [ 902]=0x11663, [ 906]=0x11664, [ 910]=0x11665,
        [ 914]=0x11666, [ 918]=0x11667, [ 922]=0x11668, [ 926]=0x11669,
        [ 930]=0x1166a, [ 934]=0x1166b, [ 938]=0x1166c, [1040]=0x029d8,
        [1044]=0x029d9, [1048]=0x029da, [1052]=0x029db, [1063]=0x0fe10,
        [1067]=0x0fe11, [1071]=0x0fe12, [1075]=0x0fe13, [1079]=0x0fe14,
        [1083]=0x0fe15, [1087]=0x0fe16, [1090]=0x0fe17, [1094]=0x0fe18,
        [1098]=0x0fe19, [1171]=0x1da87, [1175]=0x1da88, [1179]=0x1da89,
        [1181]=0x029fc, [1183]=0x1da8a, [1185]=0x029fd, [1186]=0x1da8b,
        [1188]=0x0fe30, [1192]=0x0fe31, [1196]=0x0fe32, [1200]=0x0fe33,
        [1204]=0x0fe34, [1208]=0x0fe35, [1212]=0x0fe36, [1216]=0x0fe37,
        [1220]=0x0fe38, [1224]=0x0fe39, [1228]=0x0fe3a, [1232]=0x0fe3b,
        [1233]=0x00964, [1236]=0x0fe3c, [1237]=0x00965, [1239]=0x0fe3d,
        [1243]=0x0fe3e, [1247]=0x0fe3f, [1251]=0x0fe40, [1255]=0x0fe41,
        [1259]=0x0fe42, [1263]=0x0fe43, [1267]=0x0fe44, [1271]=0x0fe45,
        [1275]=0x0fe46, [1279]=0x0fe47, [1280]=0x00970, [1283]=0x0fe48,
        [1286]=0x0fe49, [1290]=0x0fe4a, [1294]=0x0fe4b, [1298]=0x0fe4c,
        [1302]=0x0fe4d, [1306]=0x0fe4e, [1310]=0x0fe4f, [1314]=0x0fe50,
        [1318]=0x0fe51, [1321]=0x11ef7, [1322]=0x0fe52, [1325]=0x11ef8,
        [1330]=0x0fe54, [1334]=0x0fe55, [1337]=0x0fe56, [1341]=0x0fe57,
        [1345]=0x0fe58, [1349]=0x0fe59, [1353]=0x0fe5a, [1355]=0x10ead,
        [1357]=0x0fe5b, [1361]=0x0fe5c, [1365]=0x0fe5d, [1369]=0x0fe5e,
        [1373]=0x0fe5f, [1377]=0x0fe60, [1381]=0x0fe61, [1388]=0x0fe63,
        [1408]=0x0fe68, [1416]=0x0fe6a, [1420]=0x0fe6b, [1639]=0x01a1e,
        [1643]=0x01a1f, [1753]=0x1173c, [1757]=0x1173d, [1761]=0x1173e,
        [1771]=0x0a4fe, [1774]=0x0a4ff, [1833]=0x009fd, [2008]=0x0ff01,
        [2012]=0x0ff02, [2013]=0x10f55, [2016]=0x0ff03, [2017]=0x10f56,
        [2021]=0x10f57, [2024]=0x0ff05, [2025]=0x10f58, [2028]=0x0ff06,
        [2029]=0x10f59, [2031]=0x0ff07, [2035]=0x0ff08, [2039]=0x0ff09,
        [2043]=0x0ff0a, [2051]=0x0ff0c, [2055]=0x0ff0d, [2059]=0x0ff0e,
        [2063]=0x0ff0f, [2106]=0x0ff1a, [2110]=0x0ff1b, [2126]=0x0ff1f,
        [2129]=0x0ff20, [2148]=0x01aa0, [2152]=0x01aa1, [2156]=0x01aa2,
        [2160]=0x01aa3, [2164]=0x01aa4, [2168]=0x01aa5, [2172]=0x01aa6,
        [2180]=0x01aa8, [2184]=0x01aa9, [2188]=0x01aaa, [2191]=0x01aab,
        [2195]=0x01aac, [2199]=0x01aad, [2235]=0x0ff3b, [2239]=0x0ff3c,
        [2243]=0x0ff3d, [2251]=0x0ff3f, [2308]=0x00a76, [2356]=0x11fff,
        [2361]=0x0ff5b, [2369]=0x0ff5d, [2376]=0x0ff5f, [2380]=0x0ff60,
        [2384]=0x0ff61, [2388]=0x0ff62, [2392]=0x0ff63, [2394]=0x02308,
        [2396]=0x0ff64, [2398]=0x02309, [2400]=0x0ff65, [2402]=0x0230a,
        [2406]=0x0230b, [2524]=0x02329, [2527]=0x0232a, [2753]=0x1183b,
        [2786]=0x00af0, [2833]=0x0a60d, [2837]=0x0a60e, [2841]=0x0a60f,
        [2878]=0x01b5a, [2882]=0x01b5b, [2885]=0x01b5c, [2889]=0x01b5d,
        [2893]=0x01b5e, [2897]=0x01b5f, [2901]=0x01b60, [2962]=0x11047,
        [2966]=0x11048, [2970]=0x11049, [2974]=0x1104a, [2978]=0x1104b,
        [2982]=0x1104c, [2986]=0x1104d, [3063]=0x01360, [3067]=0x01361,
        [3071]=0x01362, [3075]=0x01363, [3079]=0x01364, [3083]=0x01365,
        [3087]=0x01366, [3091]=0x01367, [3095]=0x01368, [3187]=0x10857,
        [3233]=0x0a673, [3276]=0x0a67e, [3341]=0x16a6e, [3345]=0x16a6f,
        [3417]=0x110bb, [3421]=0x110bc, [3429]=0x110be, [3433]=0x110bf,
        [3437]=0x110c0, [3440]=0x110c1, [3505]=0x0037e, [3513]=0x01bfc,
        [3517]=0x01bfd, [3521]=0x01bfe, [3525]=0x01bff, [3540]=0x00387,
        [3691]=0x01400, [3731]=0x0a6f2, [3735]=0x0a6f3, [3739]=0x0a6f4,
        [3743]=0x0a6f5, [3747]=0x0a6f6, [3751]=0x0a6f7, [3760]=0x01c3b,
        [3764]=0x01c3c, [3768]=0x01c3d, [3772]=0x01c3e, [3776]=0x01c3f,
        [3792]=0x11944, [3796]=0x11945, [3800]=0x11946, [3870]=0x16af5,
        [3920]=0x1bc9f, [3938]=0x11140, [3942]=0x11141, [3946]=0x11142,
        [3950]=0x11143, [3971]=0x1091f, [4012]=0x10100, [4015]=0x10101,
        [4019]=0x10102, [4023]=0x01c7e, [4026]=0x01c7f, [4097]=0x1093f,
        [4129]=0x16b37, [4133]=0x16b38, [4137]=0x16b39, [4141]=0x16b3a,
        [4142]=0x11174, [4144]=0x16b3b, [4146]=0x11175, [4180]=0x16b44,
        [4181]=0x02cf9, [4185]=0x02cfa, [4189]=0x02cfb, [4193]=0x02cfc,
        [4200]=0x02cfe, [4204]=0x02cff, [4281]=0x01cc0, [4285]=0x01cc1,
        [4289]=0x01cc2, [4293]=0x01cc3, [4297]=0x01cc4, [4301]=0x01cc5,
        [4305]=0x01cc6, [4309]=0x01cc7, [4319]=0x00c77, [4356]=0x01cd3,
        [4370]=0x00c84, [4412]=0x119e2, [4460]=0x111c5, [4464]=0x111c6,
        [4468]=0x111c7, [4472]=0x111c8, [4491]=0x111cd, [4546]=0x111db,
        [4554]=0x111dd, [4558]=0x111de, [4562]=0x111df, [4647]=0x02d70,
        [4776]=0x11a3f, [4780]=0x11a40, [4784]=0x11a41, [4788]=0x11a42,
        [4792]=0x11a43, [4796]=0x11a44, [4800]=0x11a45, [4804]=0x11a46,
        [4911]=0x11238, [4915]=0x11239, [4919]=0x1123a, [4923]=0x1123b,
        [4927]=0x1123c, [4930]=0x1123d, [5133]=0x11a9a, [5137]=0x11a9b,
        [5141]=0x11a9c, [5149]=0x11a9e, [5153]=0x11a9f, [5157]=0x11aa0,
        [5161]=0x11aa1, [5164]=0x11aa2, [5167]=0x10a50, [5171]=0x10a51,
        [5175]=0x10a52, [5179]=0x10a53, [5183]=0x10a54, [5187]=0x10a55,
        [5190]=0x10a56, [5194]=0x10a57, [5198]=0x10a58, [5212]=0x02e00,
        [5216]=0x02e01, [5220]=0x02e02, [5224]=0x02e03, [5228]=0x02e04,
        [5232]=0x02e05, [5236]=0x02e06, [5239]=0x02e07, [5243]=0x02e08,
        [5244]=0x0a874, [5247]=0x02e09, [5248]=0x0a875, [5251]=0x02e0a,
        [5252]=0x0a876, [5255]=0x02e0b, [5256]=0x0a877, [5259]=0x02e0c,
        [5263]=0x02e0d, [5267]=0x02e0e, [5271]=0x02e0f, [5275]=0x02e10,
        [5279]=0x02e11, [5283]=0x02e12, [5287]=0x02e13, [5290]=0x02e14,
        [5294]=0x02e15, [5298]=0x02e16, [5302]=0x02e17, [5306]=0x02e18,
        [5310]=0x02e19, [5314]=0x02e1a, [5318]=0x02e1b, [5322]=0x02e1c,
        [5326]=0x02e1d, [5330]=0x02e1e, [5334]=0x02e1f, [5338]=0x02e20,
        [5341]=0x02e21, [5345]=0x02e22, [5349]=0x02e23, [5351]=0x10a7f,
        [5353]=0x02e24, [5354]=0x112a9, [5357]=0x02e25, [5361]=0x02e26,
        [5365]=0x02e27, [5369]=0x02e28, [5371]=0x0055a, [5373]=0x02e29,
        [5375]=0x0055b, [5377]=0x02e2a, [5379]=0x0055c, [5381]=0x02e2b,
        [5383]=0x0055d, [5385]=0x02e2c, [5387]=0x0055e, [5388]=0x02e2d,
        [5391]=0x0055f, [5392]=0x02e2e, [5400]=0x02e30, [5404]=0x02e31,
        [5408]=0x02e32, [5412]=0x02e33, [5416]=0x02e34, [5420]=0x02e35,
        [5424]=0x02e36, [5428]=0x02e37, [5432]=0x02e38, [5436]=0x02e39,
        [5439]=0x02e3a, [5443]=0x02e3b, [5447]=0x02e3c, [5451]=0x02e3d,
        [5455]=0x02e3e, [5459]=0x02e3f, [5463]=0x02e40, [5467]=0x02e41,
        [5471]=0x02e42, [5475]=0x02e43, [5479]=0x02e44, [5483]=0x02e45,
        [5487]=0x02e46, [5490]=0x02e47, [5494]=0x02e48, [5498]=0x02e49,
        [5502]=0x02e4a, [5506]=0x02e4b, [5510]=0x02e4c, [5514]=0x02e4d,
        [5518]=0x02e4e, [5522]=0x02e4f, [5534]=0x02e52, [5555]=0x00589,
        [5559]=0x0058a, [5597]=0x0a8ce, [5601]=0x0a8cf, [5762]=0x0a8f8,
        [5763]=0x005be, [5766]=0x0a8f9, [5770]=0x0a8fa, [5771]=0x005c0,
        [5778]=0x0a8fc, [5783]=0x005c3, [5794]=0x10af0, [5795]=0x005c6,
        [5798]=0x10af1, [5802]=0x10af2, [5806]=0x10af3, [5810]=0x10af4,
        [5813]=0x00df4, [5814]=0x10af5, [5818]=0x10af6, [5971]=0x005f3,
        [5974]=0x0a92e, [5975]=0x005f4, [5978]=0x0a92f, [6057]=0x00609,
        [6061]=0x0060a, [6069]=0x0060c, [6073]=0x0060d, [6081]=0x10b39,
        [6084]=0x10b3a, [6088]=0x10b3b, [6092]=0x10b3c, [6096]=0x10b3d,
        [6100]=0x10b3e, [6104]=0x10b3f, [6128]=0x0061b, [6129]=0x0166e,
        [6140]=0x0061e, [6144]=0x0061f, [6166]=0x0a95f, [6170]=0x00e4f,
        [6200]=0x01680, [6213]=0x00e5a, [6217]=0x00e5b, [6306]=0x0169b,
        [6310]=0x0169c, [6438]=0x0066a, [6442]=0x0066b, [6445]=0x0066c,
        [6449]=0x0066d, [6457]=0x10b99, [6461]=0x10b9a, [6465]=0x10b9b,
        [6469]=0x10b9c, [6550]=0x0a9c1, [6554]=0x0a9c2, [6558]=0x0a9c3,
        [6562]=0x0a9c4, [6566]=0x0a9c5, [6570]=0x0a9c6, [6574]=0x0a9c7,
        [6578]=0x0a9c8, [6582]=0x0a9c9, [6585]=0x0a9ca, [6589]=0x0a9cb,
        [6593]=0x0a9cc, [6597]=0x0a9cd, [6619]=0x016eb, [6623]=0x016ec,
        [6627]=0x016ed, [6642]=0x1039f, [6664]=0x0a9de, [6668]=0x0a9df,
        [6786]=0x02768, [6789]=0x02769, [6792]=0x11c41, [6793]=0x0276a,
        [6796]=0x11c42, [6797]=0x0276b, [6799]=0x11c43, [6801]=0x0276c,
        [6803]=0x11c44, [6805]=0x0276d, [6807]=0x11c45, [6809]=0x0276e,
        [6813]=0x0276f, [6814]=0x12470, [6817]=0x02770, [6818]=0x12471,
        [6821]=0x02771, [6822]=0x12472, [6825]=0x02772, [6826]=0x12473,
        [6829]=0x02773, [6830]=0x12474, [6833]=0x02774, [6835]=0x103d0,
        [6837]=0x02775, [6853]=0x006d4, [6879]=0x00f04, [6883]=0x00f05,
        [6887]=0x00f06, [6891]=0x00f07, [6895]=0x00f08, [6899]=0x00f09,
        [6903]=0x00f0a, [6907]=0x00f0b, [6910]=0x01735, [6911]=0x00f0c,
        [6914]=0x01736, [6915]=0x00f0d, [6919]=0x00f0e, [6923]=0x00f0f,
        [6926]=0x00f10, [6930]=0x00f11, [6934]=0x00f12, [6942]=0x00f14,
        [6976]=0x11c70, [6980]=0x11c71, [6993]=0x1144b, [6997]=0x1144c,
        [7001]=0x1144d, [7005]=0x1144e, [7009]=0x1144f, [7026]=0x00700,
        [7030]=0x00701, [7034]=0x00702, [7038]=0x00703, [7041]=0x00704,
        [7045]=0x00705, [7049]=0x00706, [7052]=0x1145a, [7053]=0x00707,
        [7056]=0x1145b, [7057]=0x00708, [7061]=0x00709, [7063]=0x1145d,
        [7065]=0x0070a, [7069]=0x0070b, [7073]=0x0070c, [7077]=0x0070d,
        [7091]=0x00f3a, [7095]=0x00f3b, [7099]=0x00f3c, [7103]=0x00f3d,
        [7150]=0x027c5, [7154]=0x027c6, [7158]=0x0aa5c, [7162]=0x0aa5d,
        [7166]=0x0aa5e, [7170]=0x0aa5f, [7220]=0x03000, [7223]=0x03001,
        [7227]=0x03002, [7231]=0x03003, [7251]=0x03008, [7255]=0x03009,
        [7259]=0x0300a, [7263]=0x0300b, [7267]=0x0300c, [7271]=0x0300d,
        [7274]=0x0300e, [7278]=0x0300f, [7280]=0x027e6, [7282]=0x03010,
        [7284]=0x027e7, [7286]=0x03011, [7287]=0x027e8, [7291]=0x027e9,
        [7295]=0x027ea, [7298]=0x03014, [7299]=0x027eb, [7302]=0x03015,
        [7303]=0x027ec, [7306]=0x03016, [7307]=0x027ed, [7310]=0x03017,
        [7311]=0x027ee, [7314]=0x03018, [7315]=0x027ef, [7318]=0x03019,
        [7321]=0x0301a, [7325]=0x0301b, [7329]=0x0301c, [7333]=0x0301d,
        [7337]=0x0301e, [7341]=0x0301f, [7385]=0x00f85, [7408]=0x03030,
        [7459]=0x0303d, [7475]=0x114c6, [7516]=0x16e97, [7520]=0x16e98,
        [7524]=0x16e99, [7528]=0x16e9a, [7533]=0x017d4, [7537]=0x017d5,
        [7541]=0x017d6, [7544]=0x02000, [7547]=0x02001, [7549]=0x017d8,
        [7551]=0x02002, [7553]=0x017d9, [7555]=0x02003, [7557]=0x017da,
        [7559]=0x02004, [7563]=0x02005, [7567]=0x02006, [7571]=0x02007,
        [7575]=0x02008, [7579]=0x02009, [7583]=0x0200a, [7606]=0x02010,
        [7610]=0x02011, [7614]=0x02012, [7618]=0x02013, [7622]=0x02014,
        [7626]=0x02015, [7630]=0x02016, [7634]=0x02017, [7638]=0x02018,
        [7642]=0x02019, [7645]=0x0201a, [7649]=0x0201b, [7653]=0x0201c,
        [7657]=0x0201d, [7661]=0x0201e, [7665]=0x0201f, [7668]=0x0aade,
        [7669]=0x02020, [7672]=0x0aadf, [7673]=0x02021, [7677]=0x02022,
        [7679]=0x00fd0, [7681]=0x02023, [7683]=0x00fd1, [7685]=0x02024,
        [7687]=0x00fd2, [7689]=0x02025, [7691]=0x00fd3, [7693]=0x02026,
        [7695]=0x00fd4, [7696]=0x02027, [7700]=0x02028, [7704]=0x02029,
        [7706]=0x01800, [7709]=0x01801, [7713]=0x01802, [7715]=0x00fd9,
        [7717]=0x01803, [7719]=0x00fda, [7721]=0x01804, [7725]=0x01805,
        [7728]=0x0202f, [7729]=0x01806, [7732]=0x02030, [7733]=0x01807,
        [7736]=0x02031, [7737]=0x01808, [7738]=0x0aaf0, [7740]=0x02032,
        [7741]=0x01809, [7742]=0x0aaf1, [7743]=0x02033, [7745]=0x0180a,
        [7747]=0x02034, [7751]=0x02035, [7755]=0x02036, [7759]=0x02037,
        [7763]=0x02038, [7767]=0x02039, [7771]=0x0203a, [7775]=0x0203b,
        [7779]=0x0203c, [7783]=0x0203d, [7787]=0x0203e, [7791]=0x0203f,
        [7794]=0x02040, [7798]=0x02041, [7802]=0x02042, [7806]=0x02043,
        [7814]=0x02045, [7818]=0x02046, [7822]=0x02047, [7826]=0x02048,
        [7830]=0x02049, [7834]=0x0204a, [7838]=0x0204b, [7842]=0x0204c,
        [7845]=0x0204d, [7847]=0x030a0, [7849]=0x0204e, [7853]=0x0204f,
        [7857]=0x02050, [7861]=0x02051, [7869]=0x02053, [7873]=0x02054,
        [7874]=0x1e95e, [7877]=0x02055, [7878]=0x1e95f, [7881]=0x02056,
        [7885]=0x02057, [7889]=0x02058, [7892]=0x02059, [7896]=0x0205a,
        [7900]=0x0205b, [7904]=0x0205c, [7908]=0x0205d, [7912]=0x0205e,
        [7916]=0x0205f, [7994]=0x007f7, [7998]=0x007f8, [8002]=0x007f9,
        [8034]=0x0207d, [8038]=0x0207e, [8096]=0x0208d, [8100]=0x0208e,
        [8158]=0x0104a, [8162]=0x0104b, [8166]=0x0104c, [8169]=0x0104d,
        [8173]=0x0104e, [8177]=0x0104f,
    };
    return t[(r*0x001f5e02U)>>19] == r;
}

// Decode the next rune from s, stopping before e. Returns the position
// of the next rune. The buffer must not be empty (i.e. s != e). Returns
// a REPLACEMENT CHARACTER (U+FFFD) for each invalid byte.
static uint8_t *
utf8_next(uint8_t *s, uint8_t *e, int32_t *r)
{
    int32_t a, b, c, d;
    switch (s[0]&0xf0) {
    case 0x00: case 0x10: case 0x20: case 0x30:
    case 0x40: case 0x50: case 0x60: case 0x70:
        *r = s[0];
        return s + 1;
    case 0xc0: case 0xd0:
        if (e - s < 2) break;
        a = s[0];
        b = s[1];
        *r = (a&0x1f) << 6 |
             (b&0x3f) << 0;
        if ((b&0xc0) != 0x80) break;
        if (*r < 0x80)        break;
        return s + 2;
    case 0xe0:
        if (e - s < 3) break;
        a = s[0];
        b = s[1];
        c = s[2];
        *r = (a&0x0f) << 12 |
             (b&0x3f) <<  6 |
             (c&0x3f) <<  0;
        if ((b&0xc0) != 0x80)        break;
        if ((c&0xc0) != 0x80)        break;
        if (*r < 0x0800)             break;
        if ((*r & 0xf800) == 0xd800) break;  // surrogate half
        return s + 3;
    case 0xf0:
        if (e - s < 4) break;
        a = s[0];
        b = s[1];
        c = s[2];
        d = s[3];
        *r = (a&0x0f) << 18 |
             (b&0x3f) << 12 |
             (c&0x3f) <<  6 |
             (d&0x3f) <<  0;
        if ((b&0xc0) != 0x80) break;
        if ((c&0xc0) != 0x80) break;
        if ((d&0xc0) != 0x80) break;
        if (*r < 0x01000)     break;
        if (*r > 0x10fff)     break;
        return s + 4;
    }
    *r = 0xfffd;
    return s + 1;
}

// Read the next UTF-8 rune from standard input. Returns RUNE_ERR on
// input error, and RUNE_EOF when input is exhausted. Each undecodable
// byte is replaced with REPLACEMENT CHARACTER (U+FFFD).
static int32_t
rune_next(void)
{
    #define RUNE_ERR -2
    #define RUNE_EOF -1
    static int eof;
    static uint8_t *s, *e, buf[1<<14];

    while (!eof && e-s < 4) {
        // Rune may straddle reads, so get more input
        int len = e - s;
        memmove(buf, s?s:buf, len);
        s = buf;
        e = buf + len;

        #if _WIN32
        // MSVCRT is awful, so call Win32 directly...
        DWORD n;
        HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
        if (!ReadFile(h, buf+len, sizeof(buf)-len, &n, 0)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                return RUNE_ERR;
            }
        }
        #elif __unix__ || __APPLE__
        // ...and since we're already here...
        int n = read(0, buf+len, sizeof(buf)-len);
        if (n < 0) {
            return RUNE_ERR;
        }
        #else
        int n = fread(buf+len, 1, sizeof(buf)-len, stdin);
        if (!n && ferror(stdin)) {
            return RUNE_ERR;
        }
        #endif

        e += n;
        eof = !n;
    }

    int32_t r = RUNE_EOF;
    if (s != e) {
        s = utf8_next(s, e, &r);
    }
    return r;
}

#define BUF_INIT {0, 0, 0}
#define BUF_OK   +0
#define BUF_OOM  -1
struct buf {
    size_t len, cap;
    uint8_t *data;
};

// Append a rune to the byte buffer as UTF-8. Returns BUF_OOM on
// allocation errors.
static int
buf_push(struct buf *b, int32_t r)
{
    if (!b->cap || b->len > b->cap - 4) {
        size_t cap = b->cap ? 2*b->cap : 1<<13;
        if (!cap || !(b->data = realloc(b->data, cap))) {
            return BUF_OOM;
        }
        b->cap = cap;
    }

    uint8_t *s = b->data + b->len;
    if (r >= 0x10000) {
        s[0] = 0xf0 |  (r >> 18);
        s[1] = 0x80 | ((r >> 12) & 0x3f);
        s[2] = 0x80 | ((r >>  6) & 0x3f);
        s[3] = 0x80 | ((r >>  0) & 0x3f);
        b->len += 4;
    } else if (r >= 0x800) {
        s[0] = 0xe0 |  (r >> 12);
        s[1] = 0x80 | ((r >>  6) & 0x3f);
        s[2] = 0x80 | ((r >>  0) & 0x3f);
        b->len += 3;
    } else if (r >= 0x80) {
        s[0] = 0xc0 |  (r >>  6);
        s[1] = 0x80 | ((r >>  0) & 0x3f);
        b->len += 2;
    } else {
        s[0] = r;
        b->len += 1;
    }
    return BUF_OK;
}

// Free all resources and reset the buffer to empty.
static void
buf_reset(struct buf *b)
{
    free(b->data);
    b->len = b->cap = 0;
    b->data = 0;
}

#define SET_INIT   {0, 0, 0}
#define SET_OK     +1
#define SET_EXIST  +0
#define SET_OOM    -1
struct set {
    size_t len, cap, *vals;
};

// Attempt to insert a string into the set, returning SET_OK if it was
// added or SET_EXIST if it was already in the set. Returns SET_OOM on
// allocation errors. The strings are expected to be relocatable, so the
// current base pointer must always be provided.
static int
set_insert(struct set *t, uint8_t *base, size_t off, size_t len)
{
    // String lengths first half, string offsets second half
    size_t *lens = t->vals;
    size_t *offs = t->vals + t->cap;

    if (t->len >= t->cap/2) {
        struct set n = {0, t->cap ? t->cap*2 : 1<<13, 0};
        size_t size = n.cap * 2 * sizeof(*n.vals);
        if (!size) return SET_OOM;
        n.vals = realloc(0, size);
        if (!n.vals) return SET_OOM;
        memset(n.vals, 0, size/2);  // only initialize lengths

        for (size_t i = 0; i < t->cap; i++) {
            if (lens[i]) {
                set_insert(&n, base, offs[i], lens[i]);
            }
        }

        free(t->vals);
        *t = n;
        lens = t->vals;
        offs = t->vals + t->cap;
    }

    uint64_t h = chunky64(base+off, len, t->cap);
    size_t m = t->cap - 1;
    size_t i = h & m;
    size_t s = h>>32 | 1;
    for (;;) {
        if (!lens[i]) {
            t->len++;
            offs[i] = off;
            lens[i] = len;
            return 1;
        }
        if (lens[i] == len) {
            if (!memcmp(base+offs[i], base+off, len)) {
                return 0;
            }
        }
        i = (i + s) & m;
    }
}

// Free all resources and reset the set to empty.
static void
set_reset(struct set *s)
{
    free(s->vals);
    s->len = s->cap = 0;
    s->vals = 0;
}

// Like main() but returns a static error string, or null on success.
static const char *
run(void)
{
    long long count = 0;
    struct buf buf = BUF_INIT;
    struct set set = SET_INIT;
    size_t last = buf.len;

    for (int eof = 0; !eof; ) {
        int32_t r = rune_next();
        switch (r) {
        case RUNE_ERR: return "error reading standard input";
        case RUNE_EOF: r = eof = 1;
        }

        if (!should_skip(r)) {
            if (buf_push(&buf, r) != BUF_OK) {
                return "out of memory";
            }
        } else if (last != buf.len) {
            switch (set_insert(&set, buf.data, last, buf.len-last)) {
            case SET_OOM  : return "out of memory";
            case SET_EXIST: buf.len = last; break;
            case SET_OK   : count++; last = buf.len;
            }
        }
    }

    set_reset(&set);
    buf_reset(&buf);

    fprintf(stdout, "%lld\n", count);
    fflush(stdout);
    return ferror(stdout) ? "output error" : 0;
}

int
main(void)
{
    const char *err = run();
    if (err) {
        fprintf(stderr, "uwords: %s\n", err);
        return 1;
    }
    return 0;
}

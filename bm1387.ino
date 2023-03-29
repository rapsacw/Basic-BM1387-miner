/****************************************************************************************************************************
ESP32C3 settings in tools
Board:ESP32C3 Dev module
USB CDC on boot: Enabled
Flash mode: QIO
Flash size: 4MB
Partition scheme: Default 4MB with spiffs
Erase Flash Before Sketch Upload: enabled
JTAG: ESP Usb bridge
Note: the esp32c3 is big endian, running this unmodified on a little endian system will not work, change the endianess
of the midstate send to the asics.
*****************************************************************************************************************************/

#define ap_ssid "YOUR_SSID"
#define ap_password "YOUR_WIRELESS_PW"
#define POOL_URL "solo.ckpool.org" // most other pools don't work (yet)
#define POOL_PORT 3333
#define miningaddr "YOUR_BITCOIN_ADDR"
#define miningpw ""
#define poolworker "" // change to "YOURWORKERNAME" if you want to see statistics per worker on solo.ckpool.org




//#if ARDUINO_HW_CDC_ON_BOOT
//    #define CDCSER USBSerial 
//    #define BMSER  Serial1
//#else
//    #define CDCSER Serial1
//    #define BMSER Serial 
//#endif
#define BMSER Serial1
#define CDCSER Serial

#define MAX_ASICS 4
#define _WEBSOCKETS_LOGLEVEL_     0

#include <Arduino.h>
#include <pt8211.h>
#include <WiFi.h>
//#include <WiFiClientSecure.h>
#include <ESP32AnalogRead.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include "Freenove_WS2812_Lib_for_ESP32.h"

#include "driver/gpio.h"
#include "sdkconfig.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"


// sha256 from cgminer
#ifndef SHA2_H
#define SHA2_H

#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA256_BLOCK_SIZE  ( 512 / 8)

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * SHA256_BLOCK_SIZE];
    uint32_t h[8];
} sha256_ctx;

//extern uint32_t sha256_k[64];

void sha256_init(sha256_ctx * ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void sha256_final(sha256_ctx *ctx, unsigned char *digest);
void sha256(const unsigned char *message, unsigned int len,
            unsigned char *digest);

#endif /* !SHA2_H */
#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* SHA-256 functions */

void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}










char decjsnbuf[3000]; // buffer for decoded json from pool
#define JSONBUFFER_SZ 3000 // buffer for raw json from pool


//              pool data, all ascii
// from mining.subscribe
char p_Jobid[20];     // Job id string
char p_MSubscriptid[20];  // Id for mining.subscribe/unsubscribe messages
char p_xnonce1[20];   // Extra nonce 1
char p_xnonce2sz[4];  // Extra nonce 2 size
// from mining.set_difficulty
char p_ShareDif[10];   // Share difficulty
char p_sessionid[20];    //
// from mining.notify
char p_prevblockhash[66]; // hash of previous block header
char p_coinb1[128];
char p_coinb2[400];
char p_partialmerkle[64*14+2]; // partial merkle tree
char p_version[10];
char p_nbits[10];
char p_ntime[10];
char p_clean[8];
char p_coinbase[600];   // assembled coinbase transaction
// parameters send to pool
//char p_TicketId[4];
char p_SuggestedDiff[10];

//              Mining parameters (mostly binary)
int   m_TicketDif = 0;
int   m_TicketId;
float m_tpm = 2.0;          // Target # shares per minute to pool
float m_TargetHashrate;     // Hashrate target at set frequency in GH/s
float m_AsicTargetHashrate[MAX_ASICS]; // Same but per asic
int   m_AsicValidNonces[MAX_ASICS];  // # nonces per asic
int   m_ShareDif;           // Share difficulty  for submit
uint8_t m_ShareTarget[32];  // Target for share found
uint8_t m_BlockTarget[32];  // Target for block found
uint8_t m_LowestHash[32];     // Lowest found hash

uint8_t m_version[4];
uint8_t m_prevblockhash[32];
uint8_t m_merkle[14][32];
int     m_nmerkle;
uint8_t m_xnonce2[8];
uint32_t m_xnonce2sz;
uint8_t m_nbits[4];// = {0x4a,0x54,0x8f,0xe4};
uint8_t m_ntime[4];// = {0x71,0xfa,0x3a,0x9a};
long    m_Tntime;
uint8_t m_header[80];
uint8_t m_havework = 0;   // flag to signal work from pool available
uint8_t m_mining = 0;     // flag to signal mining from pool
//            Asic parameters
typedef struct
{
  uint16_t TargetFreq;
  uint16_t RealFreq;
  float    TargetHashrate;
  long     ActiveDuration;
  int      ValidNonces;
  int      InvalidNonces;
} ASIC;
int     a_nAsics;
ASIC    a_asic[MAX_ASICS];
//           job
typedef struct {
  int     job_id;
  char    Pooljobid[20];
  uint8_t xnonce2[8];
  uint8_t ntime[4];
  uint8_t Midstate[32];
  uint8_t Work[54];
  uint8_t LastNonceResp[8];
  uint8_t LastValidNonce[4];
  uint8_t Header[80];
} Job;

Job Joba,Jobb,Jobc,Jobd,Jobe,Jobf,Jobg,Jobh;
Job *JobList[8]= {&Joba,&Jobb,&Jobc,&Jobd,&Jobe,&Jobf,&Jobg,&Jobh};

//                timers
long rt,mi,st;
//                system
uint16_t s_Vcore;
#define LittleEndian 0
#define BigEndian 1
uint8_t s_endian;

// Set up the pin names
#define pin_Enable 7
#define pin_Reset 0
//dac
#define pin_din 10
#define pin_bck 5
#define pin_ws 4
#define pin_led 6
//Vcore
#define pin_pg 9 // power good signal from buck converter, BAD choice of pin! pg=0 will stop the esp entering run mode..
// adc
#define pin_vcore 1
#define pin_temp 3

ESP32AnalogRead adc_vcore;
ESP32AnalogRead adc_temp;

/*
// Set up the pin names
#define pin_Enable 7
#define pin_Reset 0
//dac
#define pin_din 8
#define pin_bck 4
#define pin_ws 5
#define pin_led 10
*/
//nonces
#define NONCE_VALID 0
#define NONCE_DOUBLE 1
#define NONCE_STALE 2
// led
#define LEDS_COUNT  1
#define CHANNEL   1
byte m_color[5][3] = { {255, 0, 0}, {0, 255, 0}, {0, 0, 255}, {255, 255, 255}, {0, 0, 0} };
int delayval = 100;


WiFiClient poolclient;

unsigned int hh1 = 0,hh2 = 0;
unsigned int ValidNonces,ShownValidNonces,timelastshown;

const boolean invert = true; // set true if common anode, false if common cathode

#include "poolio.h"
#include "headerprep.h"

/* Vcore dac:
 *  0: 1.53V
 *  1000: 1.46
 *  2000: 1.38
 *  3000: 1.30
 *  4000: 1.22
 *  5000: 1.57
 *  6000: 1.06
 *  7000: 0.97
 *  8000: 0.90
 *  9000: 0.82
 *  a000: 0.74
 *  b000: 0.66
 *  c000: 0.58
 *  d000: 0.50
 *  e000: 0.43
 *  f000: 0.35
 *  ffff: 0.27V
 */
#define Vcore_max 1526 // 1550
#define Vcore_min 278 //268


Freenove_ESP32_WS2812 strip = Freenove_ESP32_WS2812(LEDS_COUNT, pin_led, CHANNEL, TYPE_GRB);

bool setVcore(short cv) // Set Vcore to cv millivolt
{
  float t;
  unsigned short dac;
  if(cv < Vcore_min || cv > Vcore_max) return 0; // hard bounds check
  if(cv > 800) return 0; // soft bound for 2 asics
  CDCSER.print("Setting core voltage to ");
  CDCSER.println(cv);
  s_Vcore = cv;
  cv -= Vcore_min;
  t = 65535.0 / ((float)Vcore_max - (float)Vcore_min);
  t *= (float)cv;
  dac = 0xffff - (short)t;
  PT8211_out(dac,dac);
  CDCSER.print("dac value ");
  CDCSER.println(dac);
  
  return 1;
}


void WiFiConnect()
{
  WiFi.mode(WIFI_STA);
  // for esp32-c3 and certain arduino ide versions, delete for other esp's
  //WiFi.disconnect();
  //delay(100);
  //WiFi.setTxPower(WIFI_POWER_5dBm);


  WiFi.begin(ap_ssid, ap_password);

  int i;

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    CDCSER.print(".");
  }
  delay(500);
  if(WiFi.status() == WL_CONNECTED)
  {
    CDCSER.println("WiFi connected");
    i = 0;
    while(!poolclient.connect(POOL_URL, POOL_PORT))
    {
      CDCSER.print("*");
      delay(5000);
    }
    if(!poolclient.connect(POOL_URL, POOL_PORT))
    {
      Serial.println("Connection to pool failed");
    }
    else CDCSER.println("Pool connected");
  }
  delay(200);
}

void Msha256(unsigned char *msg, size_t len,unsigned char *res)
{
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, msg, len);
  mbedtls_md_finish(&ctx, res);
  mbedtls_md_free(&ctx);
}


unsigned int crc16_table[256] = {
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
  0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
  0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
  0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
  0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
  0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
  0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
  0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
  0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
  0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
  0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
  0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
  0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
  0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
  0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
  0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
  0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
  0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
  0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
  0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
  0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
  0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
  0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

/* CRC-16/CCITT */
unsigned short crc16(const unsigned char *buffer, int len)
{
  unsigned short crc;

  crc = 0;
  while(len-- > 0)
      crc = crc16_table[((crc >> 8) ^ (*buffer++)) & 0xFF] ^ (crc << 8);

  return crc;
}

/* CRC-16/CCITT-FALSE */
unsigned short crc16_false(const unsigned char *buffer, int len)
{
  unsigned short crc;

  crc = 0xffff;
  while(len-- > 0)
      crc = crc16_table[((crc >> 8) ^ (*buffer++)) & 0xFF] ^ (crc << 8);

  return crc;
}

uint32_t bmcrc(unsigned char *ptr, uint32_t len)
{
  unsigned char c[5] = {1, 1, 1, 1, 1};
  uint32_t i, c1, ptr_idx = 0;

  for (i = 0; i < len; i++) {
    c1 = c[1];
    c[1] = c[0];
    c[0] = c[4] ^ ((ptr[ptr_idx] & (0x80 >> (i % 8))) ? 1 : 0);
    c[4] = c[3];
    c[3] = c[2];
    c[2] = c1 ^ c[0];

    if (((i + 1) % 8) == 0)
      ptr_idx++;
  }
  return (c[4] * 0x10) | (c[3] * 0x08) | (c[2] * 0x04) | (c[1] * 0x02) | (c[0] * 0x01);
}


uint8_t blk[6][161] = {"010000008e0fe627641104e55f51a736f19b4246ff5cf2830d82c6317b51450800000000608398e4ae4d57758ad0054900534d957e64cb8d50924e0f28e51e8a6fd6f127baa5c04b15112a1cb2787c03"\
                   ,"000000201929eb850a74427d0440cf6b518308837566cd6d0662790000000000000000001f6231ed3de07345b607ec2a39b2d01bec2fe10dfb7f516ba4958a42691c95316d0a385a459600185599fc5c"\
                   ,"00a0c22d51e2a4331e6d0df54e138f64f78a48ac2c3df3e42d43030000000000000000003a9b781c4034edda9bf6cdc4c15fe1b89c8371a65d0da2536fd7ac73bade67ac2e5ade632027071734409fbf"\
                   ,"00e0b827d1206fed3dd95dfe26b2ac2dd986c5be5287247ac98101000000000000000000e188f54eaf56db85c22917f482f0918ed201cc6ba0da4018a6d4be1d43648b11bf5bde632027071778d866ec"\
                   ,"00e00020025ab75d6fd1d6eb279e71874b98de591984153e134c05000000000000000000bb7e5313234ba04a48e7c327abd03efbde0d65a37ffad9e72b3e350ca54d97cf665fde6320270717f98d5f43"\
                   ,"000000201ccf1f76ab93ea52e22e753f1b3a040c498434141d8a020000000000000000003483c0701c22fbe12e335888ecebf204742d2821c624f0aef02e412d334b9caf9a5fde6320270717edcb6a1b"};

char wrk[] = "2136750100000000F91E0E178020CC603AECC01748C5543805061AA345D74CA10DB6445F0C8562F297B4AE270333ABEE11A8935C";




void showcommand(unsigned char *buf, int len)
{
  int i;

  for(i=0;i<len;i++)
  {
    CDCSER.print(hexily(buf[i]>>4));
    CDCSER.print(hexily(buf[i]&0xf));
    CDCSER.print(' ');
  }
  CDCSER.println();
}

int readresponse(unsigned char *buf)
{
  int i = 0;
  
  if (BMSER.available())
    while(BMSER.available()&& i<1024)
    {
      buf[i++] = BMSER.read();
    }
  return i;
}

void showresponse(uint8_t *buf, int len)
{ int j;
  for(j=0;j<len;j++)
  {
    CDCSER.print(hexily(buf[j]>>4));
    CDCSER.print(hexily(buf[j]&0xf));
    //CDCSER.print(' ');
  }
}

void readandshow()
{
  uint8_t buf[1024];
  int i,j;

  i = readresponse(buf);
  for(j=0;j<i;j++)
  {
    CDCSER.print(hexily(buf[j]>>4));
    CDCSER.print(hexily(buf[j]&0xf));
    CDCSER.print(' ');
  }
  CDCSER.println();
}

void sendcrc5(unsigned char *buf, int len)
{
  unsigned char crc;
  int i;

  buf[len-1] |= bmcrc(buf,(len-1)*8);
  BMSER.write(buf,len);
  showcommand(buf,len);
}

void BM1387flush(void)
{
  while(BMSER.available()) BMSER.read();
}



// bm1387 work data
//
// 0x21 len id #ms 0 0 0 0 hsh3 midstate <midstate2> .. <midstate4> crc
//where
// 0x21 is work command
// len = total message length, should be 4(cmd+para)+16(last part of blockheader incl. nonce)+32*#midstates+2(crc)
// id = job id
// #ms = number of midstates
// 0 0 0 0 = starting nonce
// hsh3 = byte reversed remainder of blockheader (12 bytes)
// midstate = byte reversed hash of 1st 64 bytes of header
// crc = 16 bit crc
static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
static const double bits192 = 6277101735386680763835789423207666416102355444464034512896.0;
static const double bits128 = 340282366920938463463374607431768211456.0;
static const double bits64 = 18446744073709551616.0;

uint64_t array2ui64(uint8_t *p)
{
  int i;
  uint64_t res;

  res = 0;
  for(i=0;i<8;i++)
  {
    res *= 256;
    res |= p[i];
  }
  return res;
}

double le256todouble(uint8_t *target)
{
  uint64_t data64;
  double dcut64;

  data64 = array2ui64(&target[0]);
  dcut64 = (double)data64 * bits192; //le64tobin(data64) * bits192;

  data64 = array2ui64(&target[8]);
  dcut64 += (double)data64 * bits128; //le64tobin(data64) * bits128;

  data64 = array2ui64(&target[16]);
  dcut64 += (double)data64 * bits64; //le64tobin(data64) * bits64;

  data64 = array2ui64(&target[24]);
  dcut64 += (double)data64; //le64tobin(data64);

  return dcut64;
}


// Return a difficulty from a hash
int diff_from_target(uint8_t *target)
{
  double dft,d64, dcut64;
  char b[80];

  d64 = truediffone;
  dcut64 = le256todouble(target);
  if (dcut64<1)
    dft = 1;
  else
    dft = (double)(d64 / dcut64);
  int idft = (int)(dft+0.001); // round
  return idft;
}

/*
 * Submit share to pool
 */
void do_submit(void *p)
{
  char nonc[10];
   char tim[10];
  char xno2[20];
  uint8_t xn2[10];
  char ticketid[10];
  Job *j;
  uint8_t foundnonce[4];

  j = (Job *)p;
  foundnonce[0] = j->LastNonceResp[3];
  foundnonce[1] = j->LastNonceResp[2];
  foundnonce[2] = j->LastNonceResp[1];
  foundnonce[3] = j->LastNonceResp[0];
  bintostr(foundnonce, nonc, 4);
  bintostr(j->ntime, tim, 4);
  bintostr(j->xnonce2, xno2, m_xnonce2sz);
  m_TicketId++;
  if(m_TicketId>1000) m_TicketId = 0;
  itoa(m_TicketId,ticketid,10);
  poolSubmit(xno2, tim, nonc, j->Pooljobid, ticketid);
}


int CheckAgainstTarget(uint8_t *hash, uint8_t *target) // return 1 for hash<target
{
  int res = 1;
  int i;
  i = 0;
  while(i<32)
  {
    if(hash[i] < target[i])
    {
      break;
    }
    if(hash[i] > target[i])
    {
      return 0;
    }
    i++;
  }
  return res;
}

// Check nonce crc and minimum difficulty
int CheckNonce(void *ptr) // return 1 for valid nonce
{
  uint8_t valid;
  uint8_t hash[32];
  uint8_t finalhash[32];
  //uint8_t headr[80];
  int i;
  Job *j;
  uint8_t *p,digest[32];

  j = (Job *)ptr;
  valid = 1;
  j->LastNonceResp[7] = 0x80;
  uint8_t n1 = bmcrc(j->LastNonceResp, 6*8+3);

  n1 |= 0x80;
  if (n1 != j->LastNonceResp[6]) 
  {
    valid = 0;
    CDCSER.print("CRC FAULT");
  }
  else // check hash result
  {
    // verify nonce by midstate
    sha256_ctx ctx;
    uint8_t hash_rest[16];

    sha256_init(&ctx);
    // verify nonce using midstate
    // copy midstate to sha256 context
    ctx.tot_len=64;
    ctx.len=0;
    p = (uint8_t *)ctx.h;
    //for(i=0;i<32;i++) p[i] = j->Midstate[31-i]; // restore midstate reversed
    for(i=0;i<32;i++) p[i] = j->Midstate[i]; // restore midstate

    j->Header[76] = j->LastNonceResp[0]; // insert nonce
    j->Header[77] = j->LastNonceResp[1];
    j->Header[78] = j->LastNonceResp[2];
    j->Header[79] = j->LastNonceResp[3];
    sha256_update(&ctx,&j->Header[64],16); // hash it
    sha256_final(&ctx, digest);
    sha256_init(&ctx);
    sha256_update(&ctx,digest,32); // hash it again
    sha256_final(&ctx, digest);
/*    // verify nonce by full header
    j->Header[76] = j->LastNonceResp[0]; // insert nonce
    j->Header[77] = j->LastNonceResp[1];
    j->Header[78] = j->LastNonceResp[2];
    j->Header[79] = j->LastNonceResp[3];
    sha256_init(&ctx);
    sha256_update(&ctx,j->Header,80); // hash it
    sha256_final(&ctx, digest);
    sha256_init(&ctx);
    sha256_update(&ctx,digest,32); // hash it again
    sha256_final(&ctx, digest);*/

    memcpy_reverse(finalhash,digest,32);
    if ((j->Work[2]>0x1f) && CheckAgainstTarget(finalhash,m_ShareTarget)) // only submit tickets with mining id, not warmup id
    {
      CDCSER.println();
      do_submit(ptr);
      //CDCSER.print("Asic work: "); showresponse(j->Work,52); CDCSER.println();
      //CDCSER.println("Header: "); showresponse(j->Header,80); CDCSER.println();
      //CDCSER.println("Hash:   "); showresponse(finalhash,80); CDCSER.println();

      delay(20);
    }
    if(CheckAgainstTarget(finalhash,m_LowestHash))
    {
      memcpy(m_LowestHash,finalhash,32);
    }
    //CDCSER.print(" ");
    //showresponse(finalhash, 32);
    //CDCSER.println();
    //showresponse(j->Header,80);
    //CDCSER.println();
  }
  return valid;
}

uint8_t twork[] = {
0x21, 0x36, 0x33, 0x01,
0x00 ,0x00 ,0x00 ,0x00 ,0x87 ,0x32 ,0x0b ,0x1a ,0x14 ,0x26 ,0x67 ,0x4f ,0x2f ,0xa7 ,0x22 ,0xce,
0x46 ,0x79 ,0xba ,0x4e ,0xc9 ,0x98 ,0x76 ,0xbf ,0x4b ,0xfe ,0x08 ,0x60 ,0x82 ,0xb4 ,0x00 ,0x25,
0x4d ,0xf6 ,0xc3 ,0x56 ,0x45 ,0x14 ,0x71 ,0x13 ,0x9a ,0x3a ,0xfa ,0x71 ,0xe4 ,0x8f ,0x54 ,0x4a,
0x00,0x00
};

/*
 * AddJob
 * Sends new work to asics
 */
void AddJob(unsigned int count)
{
  Job *j;
  uint16_t crctje;
  int i,ind;
  int len;
  sha256_ctx ctx;
  uint8_t *p;
  

  ind = count & 0x7; // 8 in job list
  j = JobList[ind];
  if(m_mining)  // mining on pool (eg asics warmed up & pool data received)
  {
    // keep relevant job info in job struct
    memcpy(j->xnonce2,m_xnonce2,m_xnonce2sz); // copy xnonce2
    memcpy(j->ntime,m_ntime,4); // copy ntime
    strcpy(j->Pooljobid,p_Jobid); // copy pool's jobid
    // make a copy of this header
    memcpy(j->Header,m_header,80); // copy blockchain header to job
    // calculate midstate for this job
    sha256_init(&ctx);
    sha256_update(&ctx,j->Header,64);
    p = (uint8_t *)ctx.h;
    memcpy(j->Midstate, p, 32); // keep copy of midstate in job
    // assemble work
    j->Work[0] = 0x21;
    j->Work[1] = 0x36;
    j->Work[2] = 0x20+(count&0x1f);
    j->Work[3] = 1;
    memcpy(&j->Work[4],&zeroes_4,4); // clear nonce field
    memcpy(&j->Work[8],&j->Header[72],4); // copy nbits
    memcpy(&j->Work[12],&j->Header[68],4); // copy ntime
    memcpy(&j->Work[16], &j->Header[64],4); // copy last 4 bytes of merkle
    memcpy_reverse(&j->Work[20],j->Midstate,32); // copy reversed midstate, change this for little endian systems

    crctje = crc16_false(j->Work,52);
    j->Work[52] = crctje>>8;
    j->Work[53] = crctje&0xff;
    BMSER.write(j->Work,54);
    //CDCSER.print("Work:");
    //showresponse(j->Work,54);
    //CDCSER.println();
    Header_nextjob();
  }
  else // warming up
  {
    memcpy(&j->Work,twork,8); // command(4) + nonce(4)
    j->Work[2] = count&0x1f; // jobid

    for(i=4;i<52;i++)
      j->Work[i] = (i>20)? rand()%256: twork[i]; // random work
    crctje = crc16_false(j->Work,52);
    j->Work[52] = crctje>>8;
    j->Work[53] = crctje&0xff;
    BMSER.write(j->Work,54);
  }
}
/*
 * HandleNonce
 * test nonces from asics, updates statistics, shows activity on led
 */
int HandleNonce(int *invalids) // return #valid nonces
{
  uint8_t buf[1024];
  int v,len,i,k,vn,ind;
  Job *j;

  len = readresponse(buf);
  vn = i = 0;
  while(i<len)
  {
    ind = buf[i+5]; // JobId
    for(k=0;k<8;k++)
    {
      j = JobList[k];
      if(j->Work[2] == ind) break;
    } 
    if(k == 8)
    {
        CDCSER.println("-!JobID, stale-");
        (*invalids)++;
        continue;
    }
    if(memcmp(&buf[i],j->LastNonceResp,4) != 0) // New not seen b4 nonce?
    {
      memcpy(j->LastNonceResp,&buf[i],7);
      //showresponse(&buf[i],7);
      // test validity here
      v = CheckNonce(j);
      if(v)
      {
        unsigned int asic = buf[i] / (0x100 / (a_nAsics));
        a_asic[asic].ValidNonces++; 
        vn++;
      }
      //CDCSER.println("");
    }
    // else its a double or has a stale/invalid id
    else 
    {
      CDCSER.print("(");
      showresponse(&buf[i],7);
      CDCSER.println(")");
      (*invalids)++;
    }
    i += 7;
  }
  if((ValidNonces+vn) > ShownValidNonces && (millis() - timelastshown) > 25)
  {
    strip.setLedColorData(0,rand()%256, rand()%256, rand()%256);
    strip.show();
    timelastshown = millis();
    ShownValidNonces++;
  }
  return vn;
}
//

/*uint8_t tdat1[] = {
0x21, 0x36, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00  
};
uint8_t tdat2[] = {
0x21, 0x36, 0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0xF9, 0x1E, 0x0E, 0x17, 0x80, 0x20, 0xCC, 0x60,
0x61, 0x81, 0x55, 0x05, 0x00, 0x36, 0x06, 0x53, 0x32, 0x62, 0xA2, 0x41, 0x21, 0xA0, 0x3C, 0xB2,
0x43, 0xE3, 0xC0, 0x53, 0x49, 0xFC, 0x20, 0x7A, 0x9D, 0x5D, 0xE0, 0x84, 0xE6, 0x62, 0x14, 0x75,
0x99, 0xCB, 0x96, 0x9C  
};
uint8_t tdat3[] = {
0x21, 0x36, 0x75, 0x01, 0x00, 0x00, 0x00, 0x00, 0xF9, 0x1E, 0x0E, 0x17, 0x80, 0x20, 0xCC, 0x60,
0x3A, 0xEC, 0xC0, 0x17, 0x48, 0xC5, 0x54, 0x38, 0x05, 0x06, 0x1A, 0xA3, 0x45, 0xD7, 0x4C, 0xA1,
0x0D, 0xB6, 0x44, 0x5F, 0x0C, 0x85, 0x62, 0xF2, 0x97, 0xB4, 0xAE, 0x27, 0x03, 0x33, 0xAB, 0xEE,
0x11, 0xA8, 0x93, 0x5C
};*/

#define FREQ_STEP 5       // Choose step size so that 750/STEP_SIZE is an integer
#define MIN_FREQ 50       // do not change!
#define MAX_FREQ 799      // don't go over 799

uint16_t ftable[(MAX_FREQ-50)/FREQ_STEP]; // Parameters 5 & 7 for BM1387 set frequency command

int BM1387Frequency(int freq)
{
  uint8_t frcommand[] = {0x58, 0x09, 0x00, 0x0C, 0x00, 0x50, 0x02, 0x41, 0x00};
  uint16_t regs;

  if(freq < MIN_FREQ || freq>MAX_FREQ) { Serial.println("Invalid frequency, not set."); return 0; }
  Serial.print("Requested frequency: ");
  Serial.print(freq);
  regs = ftable[(freq-50)/FREQ_STEP];
  frcommand[5] = regs>>8;
  frcommand[7] = regs&0xff;
  CDCSER.print("MHz, set frequency: ");
  float rf = frcommand[5] * 25.0;
  rf /= (frcommand[7]>>4);
  rf /= (frcommand[7]&0x7);
  rf /= 2;
  Serial.print((int)rf);
  Serial.println("MHz");
  sendcrc5(frcommand,9);
  delay(10);
  m_TargetHashrate = 0;
  for(int i=0;i<a_nAsics;i++)
  {
    a_asic[i].TargetHashrate = rf * 0.114;
    m_TargetHashrate += a_asic[i].TargetHashrate;
    a_asic[i].RealFreq = (uint16_t)rf;
    a_asic[i].TargetFreq = (uint16_t)freq;
    a_asic[i].ActiveDuration = millis();
  }
  return 1;
}

int BM1387FrequencySingle(int freq,int asic)
{
  uint8_t frcommand[] = {0x48, 0x09, 0x00, 0x0C, 0x00, 0x50, 0x02, 0x41, 0x00};
  uint16_t regs;

  if(freq < MIN_FREQ || freq>MAX_FREQ) { Serial.println("Invalid frequency, not set."); return 0; }
  if(asic < 0 || asic > (MAX_ASICS-1)) { Serial.println("Invalid asic#, not set."); return 0; }
  m_TargetHashrate -= a_asic[asic].TargetHashrate;
  frcommand[2] = (0x100 / a_nAsics) * asic;
  CDCSER.print("Requested frequency for asic#");
  CDCSER.print(asic);
  CDCSER.print(": ");
  CDCSER.print(freq);
  regs = ftable[(freq-50)/FREQ_STEP];
  frcommand[5] = regs>>8;
  frcommand[7] = regs&0xff;
  CDCSER.print("MHz, set frequency: ");
  float rf = frcommand[5] * 25.0;
  rf /= (frcommand[7]>>4);
  rf /= (frcommand[7]&0x7);
  rf /= 2;
  CDCSER.print((int)rf);
  CDCSER.println("MHz");
  sendcrc5(frcommand,9);
  delay(10);
  a_asic[asic].TargetHashrate = rf * 0.114;
  a_asic[asic].RealFreq = (uint16_t)rf;
  a_asic[asic].TargetFreq = (uint16_t)freq;
  m_TargetHashrate += a_asic[asic].TargetHashrate;
  a_asic[asic].ActiveDuration = millis();
  return 1;
}

// recursive routine to find nearest/lower frequency if exact match isn't possible
int findnearest(uint16_t *m,int i,int offset)
{
  int rv;

  rv = 0;
  if((i+offset)<750)
  {
    if(m[i+offset]) rv = i+offset;
  }
  if((i-offset)>=50)
  {
    if(m[i-offset]) rv = i-offset; // overwrites higher solution if present
  }
  if(rv == 0) rv = findnearest(m,i,offset+1); // nothing found yet, search wider
  return rv;
}

void maketable()
{
  uint16_t mult[750];
  int i,m,d,e;

  for(i=0;i<750;i++) mult[i] = 0;
  // find register entries for all possible (integer)frequencies from 50 .. 799MHz
  for(m=33;m<128;m+=1)
  {
    for(d=1;d<7;d++)
    {
      for(e=1;e<7;e++)
      {
        float f;

        f = (m*25.0); // multiplier
        f /= (float)d; // divider 1
        f /= (float)e; // divider 2
        f /= 2;
        if((f >= 50.0) && (f < 800.0))
        {
          int freq = (int)(f+0.5);
          freq -= 50;
          if(!mult[freq]) // keep entry with lowest multiplier for energy efficiency
          {
            mult[freq] = m << 8;
            mult[freq] |= d<< 4;
            mult[freq] |= e;
          }
        }
      }
    }
  }
  // now compress results to a table with FREQ_STEP MHz resolution
  for(i=0;i<((MAX_FREQ-50)/FREQ_STEP);i++)
  {
    uint16_t value;
    char str[5];

    if(mult[i*FREQ_STEP] == 0)
    {
      int j;
      j = findnearest(mult,i*FREQ_STEP,1);
      value = mult[j];
    }
    else value = mult[i*FREQ_STEP];
    ftable[i] = value;
  }
}

// set ticketmask so lowest reported dif = 2^(i-1)*dif@1
int BM1387SetTicketMask(int i)
{
  unsigned char ticketmask[] = { 0x58, 0x09, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00};
// 0xff: /2 // not allowed
// 0xfe: /128
// 0xfc: /64
// 0xf8: /32
// 0xf0: /16
// 0xe0: /8
// 0xc0: /4
// 0x80: /2
// 0x00: /1

  uint16_t mask = 0xff00;
  if(i<1 || i>7) return 1; // error
  m_TicketDif = i;
  i -= 1;
  mask >>= i;
  ticketmask[7] = mask;
  sendcrc5(ticketmask,9);
  delay(5);
  return 0;
}

int BM1387SetDifficulty(int dif)
{
  uint8_t h = 1;
  char sd[10];
  int i,j;

  strcpy(sd,p_ShareDif);
  j = strlen(p_ShareDif);
  j--;
  while(j && p_ShareDif[j] == '0') sd[j--] = 0; // Strip trailing zeroes
}

/*
 * Detect # asics
 */
char BM1387GetNchips()
{
  int i,j;
  unsigned char dat;
  unsigned char buf[1024];
  char nchips;
    
  BM1387flush();
  delay(10);
  uint8_t frdat[] = { 0x54, 0x05, 0x00, 0x00, 0x00 };
  sendcrc5(frdat,5);
  delay(100);
  if (BMSER.available())
  {
    CDCSER.println();
    i = readresponse(buf);
    j = 0;
    while (j<i)
    {
      dat = buf[j++];
      CDCSER.print(hexily(dat>>4));
      CDCSER.print(hexily(dat&0xf));
      CDCSER.print(" ");
    }
  }
  nchips = i/7;
  return nchips;
}

/*
 * init asics
 */
void BM1387Inactive()
{
  unsigned char buffer[5] = {0x55, 0x05, 0x00, 0x00, 0x00 };
  int i,j;

  a_nAsics = BM1387GetNchips();
  CDCSER.println();
  CDCSER.print((int)a_nAsics);
  CDCSER.println(" chips found.");
  if (!a_nAsics) { CDCSER.println("HALTED"); while(1); }

  for(j=0;j<3;j++)
  {
    sendcrc5(buffer,5);
    delay(5);
  }


  for(j=0;j<a_nAsics;j++)
  {
    buffer[0] = 0x41;
    buffer[1] = 0x05;
    buffer[2] = (0x100 / (a_nAsics)) * j;
    buffer[3] = (0x100 / (a_nAsics)) * j;// 0;
    sendcrc5(buffer,5);
    delay(5);
  }
  delay(10);
  // baud_div = min(OSC/(8*baud) - 1, 26)
  // Oscillator frequency is 25 MHz
  unsigned char baudrate[] = { 0x58, 0x09, 0x00, 0x1C, 0x00, 0x20, 0x07, 0x00, 0x19};
  //bauddiv = 0x19 # 115200
  //bauddiv = 0x0D # 214286
  //bauddiv = 0x07 # 375000

  baudrate[6] = 0x19;
  sendcrc5(baudrate,0x9);
  //BMSER.begin(214286, SERIAL_8N1,20,21);
  delay(10);
  unsigned char gateblk[10] = {0x58, 0x09, 0x00, 0x1C, 0x40, 0x20, 0x99, 0x80, 0x01};
  gateblk[6] = 0x80 | baudrate[6];
  sendcrc5(gateblk,9);
  delay(20);
  //unsigned char ticketmask[] = { 0x58, 0x09, 0x00, 0x18, 0x00, 0x00, 0x00, 0xc0, 0x00};
  //unsigned char ticketmask[] = { 0x58, 0x09, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00};
  //sendcrc5(ticketmask,9);
  delay(100);
  CDCSER.println();
}


/*
 * Calculate ShareTarget, target@diff = target@diff1/diff
 */
void MakeShareTarget()
{
  uint8_t dif1[34],res[32];
  int divid = atoi(p_ShareDif);
  int index,ri;
  int i,h;
  uint8_t temp;

  for(i=0;i<33;i++) dif1[i] = (i<4 || i>7)? 0:0xff;
  
  ri = index = 0;
  h = dif1[index];

  while(index<32)
  {
    temp = h / divid;
    res[ri] = temp;
    h = h % divid;
    ri++;
    index++;
    h = h<<8 | dif1[index];
  }
  
  CDCSER.print("Share target for diff:"); CDCSER.print(divid); CDCSER.print(": ");
  showresponse(res,32);
  memcpy(m_ShareTarget,res,32);
  CDCSER.println();
}

/*
 * Calculate needed difficulty to get m_tpm shares per minute at m_TargetHashrate (and thus set frequency)
 */
void CalcPoolSuggestedDif(void)
{
  float dif;
  int difi;

  dif = (m_TargetHashrate/4.3*60) / m_tpm;
  difi = (int)dif;
  strcpy(p_SuggestedDiff,itoa(difi,p_SuggestedDiff,10));
}

void setup()
{
  int i,j;
  unsigned short data;
  long t;
  char endian[2][20] = { "Little endian","Big endian" };


    
  // Init I/O & hardware
  pinMode(pin_Enable,OUTPUT);
  digitalWrite(pin_Enable,LOW);
  pinMode(pin_Reset,OUTPUT);
  digitalWrite(pin_Reset, LOW);
  PT8211_init(pin_din,pin_bck,pin_ws);
  setVcore(Vcore_min);
  // serial
  BMSER.begin(115200, SERIAL_8N1,20,21);
  CDCSER.begin(115200);
  delay(1000);
  uint32_t testint = 0x04030201;
  CDCSER.print("System endian test: ");
  if (*((uint8_t *)&testint) == 0x01) s_endian = BigEndian;
  else s_endian = LittleEndian;
  CDCSER.println(endian[s_endian]);
  CDCSER.print("Size of double: ");
  CDCSER.println(sizeof(double));
  CDCSER.print("Size of uint64_t: ");
  CDCSER.println(sizeof(uint64_t));
  
  delay(100);
  adc_vcore.attach(pin_vcore);
  //adc_temp.attach(pin_vcore);




  // asic related init
  maketable();
  //pinMode(pin_pg,INPUT_PULLUP);
  setVcore(690); // 100MHz@630mV/150MHz@660mV/175MHz@676mV/200MHz@690mV/225MHz@715mV/275MHz@730mV/300MHz@750mV(3.1W)/325MHz@800mV/350MHz@850mV 
  delay(300);
  digitalWrite(pin_Enable,HIGH);
  delay(500);
  BMSER.flush();

/*  while(1)
  {
    CDCSER.println("0xf000");
    PT8211_out(0xf000,0xf000); //.357 min=0.278
    delay(3000);
//
    CDCSER.println("0xe000");
    PT8211_out(0xe000,0xe000); //.435
    delay(3000);              
    CDCSER.println("0xd000");
    PT8211_out(0xd000,0xd000); //.514 max=1.526
    delay(3000);
    CDCSER.println("0xc000");
    PT8211_out(0xc000,0xc000); //.591
    delay(3000);              
             
  }*/


  digitalWrite(pin_Reset, HIGH);
  delay(10);
  BM1387Inactive();
  delay(100);
  BM1387Frequency(168);
  //BM1387FrequencySingle(125,1);
  CalcPoolSuggestedDif();
  BM1387SetTicketMask(1);
  delay(100);

  strip.begin();
  strip.setBrightness(5);
  strip.setLedColorData(0,rand()%2, rand()%2, rand()%2);
  strip.show();

  //srand(esp_random());
  //srand(123);
  delay(100);
  // wifi
  WiFiConnect();  
  CDCSER.print("Wifi Client started @ IP address: ");
  CDCSER.println(WiFi.localIP());
  
  poolConnect();
  m_xnonce2sz = atoi(p_xnonce2sz);
  if(m_xnonce2sz>8) { CDCSER.println("Xnonce2 size too big!");}
  delay(100);
  rt = timelastshown = st = mi = millis();
  ShownValidNonces = ValidNonces = 0;
  m_mining = m_havework = 0;
  for(i=0;i<32;i++) m_LowestHash[i] = 0xff;
  CDCSER.println("Init done");
  delay(1000);
}



void loop()
{

  int i,len;
  uint8_t buf[1024];
  uint8_t dat;
  long t;
  static unsigned int jobcount = 0;
  static unsigned int inter = 60;
  static int invalids = 0;
  int br = 0;

  float hr = m_TargetHashrate/4.3;
  hr = 1.0 / hr;
  inter = (int)((hr/2)*1000.0);
  if(!m_mining) inter = inter / 4;

  

  t = millis();
  if(millis()-st > 60000 && s_Vcore != 668) setVcore(668);
  if((t-mi)> inter)
  {
    jobcount++;
    AddJob(jobcount);

    if((t-rt)>5000)//(jobcount % 128 == 0)
    {
      rt = t;
      CDCSER.println();
      CDCSER.println("-----------------------------------------------------------------------------------");
      CDCSER.print("Hashrate (target:");
      CDCSER.print(m_TargetHashrate);
      CDCSER.print("GHs): ");
      float hrr = (float)ValidNonces*4.2949673*(1<<(m_TicketDif-1))/ ((float)(millis()-st)/1000.0);
      CDCSER.print(hrr);CDCSER.println("GHs");
      for(int ac = 0;ac<a_nAsics;ac++)
      {
        CDCSER.print("asic#"); CDCSER.print(ac); CDCSER.print(":"); 
        float hr = (float)a_asic[ac].ValidNonces*4.2949673*(1<<(m_TicketDif-1))/ ((float)(millis()-a_asic[ac].ActiveDuration)/1000.0);
        CDCSER.print(hr);CDCSER.print("GHs ");
      }
      CDCSER.println();
      
      CDCSER.print("Job interval (ms): ");
      CDCSER.print(inter);
      CDCSER.print(" Vcore:"); CDCSER.print(adc_vcore.readVoltage()); CDCSER.print(" Status: ");
      if(!m_mining) CDCSER.print("-warming up- ");
      else CDCSER.print("-mining- ");
      if(!m_havework) CDCSER.println("-no pool data-");
      else 
      {
        CDCSER.print("-pool active-");
        CDCSER.print("-pool diff: ");
        CDCSER.print(p_ShareDif);
        CDCSER.println("-");
      }
      CDCSER.print("Best: ");
      showresponse(m_LowestHash,32);
      CDCSER.println();
      //CDCSER.print("Highest difficulty found: ");
      //float hd = (float)diff_from_target(m_LowestHash);
      //CDCSER.println(hd);


      CDCSER.println("-----------------------------------------------------------------------------------");

      if ((inter>15) && (invalids > 2) && ((t-mi-inter)<2)) 
      {
        if(inter<19) inter -= 1;
        else inter-=3;
        ShownValidNonces = ValidNonces = 0;
        st = millis();
      }
      invalids = 0;
      if((!m_mining) && m_havework && (hrr > (m_TargetHashrate*.8)) &&((millis()-st) > 40000)) // done warming up?
      {
        m_mining = 1;
      }
    }

    //CDCSER.println();
    //CDCSER.print(jobcount%128);
    //CDCSER.print(": ");
    mi = t;

  }

  if(BMSER.available())
  {
    ValidNonces += HandleNonce(&invalids);
  }

  if(poolclient.available())
  {
    pool_message();
    if(m_havework) header_makebin();
  }
}

/*
 * Prepare block header from pool data
 * increments ntime & xnonce2 for new jobs
 */

#define ROLLNTIME 1
#define ROLLXN2 1

int zeroes_4 = 0;
#define zeroes_8 "00000000"


// ascii<>bin conversions
char hexily(unsigned char d) // return hex representation of 1 nibble
{
  if(d<=9) return '0'+d;
  return 'a'+d-10;
}

void bintostr(uint8_t *bin, char *str, int binlen)
{
  int i;
  
  for(i=0;i<binlen;i++)
  {
    str[i*2] = hexily(bin[i]>>4);
    str[i*2+1] = hexily(bin[i]&0xf);
  }
  str[i*2]=0;
}

// increment a LE hex string, overflows to zeroes
void inc_hexstr(char *p,int len)
{
  int i,cont;

  i = len-1;
  cont = 1;
  do
  {
    switch(p[i])
    {
      case '9': p[i] = 'a'; cont = 0; break;
      case 'f': p[i] = '0'; i--; break;
      default: p[i]++; cont = 0;
    }
  } while (cont && i>=0);
}


void inc_4bin(uint8_t *p) // increment 4 byte integer the hard way (for endian independence), overflows to zeroes
{
  int i = 3;
  int cont = 1;
  while(cont && i >= 0)
  {
    if(p[i]<=254)
    {
      p[i]++;
      cont=0;
    }
    else
    {
      p[i] = 0;
      i--;
    }
  }
}

void inc_nbin(uint8_t *p,uint8_t n) // increment n-byte integer the hard way (for endian independence), overflows to zeroes
{
  int i = n-1;
  int cont = 1;
  while(cont && i >= 0)
  {
    if(p[i]<=254)
    {
      p[i]++;
      cont=0;
    }
    else
    {
      p[i] = 0;
      i--;
    }
  }
}


uint8_t nibble2bin(char nib)
{
  if((nib>='0') && (nib <='9')) return nib-'0';
  if((nib>='a') && (nib <= 'f')) return nib-'a'+10;
  if((nib>='A') && (nib <= 'F')) return nib-'A'+10; //!! should never happen !!
}

int hexstr2bin(char *str, uint8_t *buf)
{
  int i;

  i = 0;
  while(str[i])
  {
    buf[i/2] = (nibble2bin(str[i]) << 4) | nibble2bin(str[i+1]);
    i += 2;
  }
  return i/2;
}

void hexstrn2bin(char *str, uint8_t *bin, int binlen)
{
  int i;

  i = 0;
  for(i=0;i<binlen*2;i+=2)
  {
    bin[i/2] = (nibble2bin(str[i]) << 4) | nibble2bin(str[i+1]);
  }
}


void memcpy_reverse(void *dst, void *src,int len)
{
  int i;
  for(i=0;i<len;i++)
  {
    ((uint8_t *)dst)[i] = ((uint8_t *)src)[len-i-1];
  }
}

void nBits2Target(void)
{
  int nb1;

  memset(m_BlockTarget,0,32); // clear target
  nb1 = m_nbits[0] - 3;
  m_BlockTarget[29-nb1] = m_nbits[1];
  m_BlockTarget[30-nb1] = m_nbits[2];
  m_BlockTarget[31-nb1] = m_nbits[3];
  //CDCSER.println("Block target:");
  //showresponse(m_BlockTarget,32);
  //CDCSER.println();
}

/*
 *  Double hash
 */
void mbedDblHash(uint8_t *digest, void *src, int len)
{
  uint8_t sha_res[32];
  
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (uint8_t *)src, len);
  mbedtls_md_finish(&ctx, sha_res);
  mbedtls_md_free(&ctx);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, sha_res, 32);
  mbedtls_md_finish(&ctx, digest);
  mbedtls_md_free(&ctx);
}

void DblHash(uint8_t *digest, void *src, int len)
{
  uint8_t sha_res[32];
  
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx,(uint8_t *)src,len); // hash it
  sha256_final(&ctx, sha_res);
  sha256_init(&ctx);
  sha256_update(&ctx,sha_res,32); // hash it again
  sha256_final(&ctx, digest);
}


/*
 * Assemble coinbase transaction
 */
void Header_makecoinbase(void)
{
  char xnonc2[18];
  
  strcpy(p_coinbase,p_coinb1);
  strcat(p_coinbase,p_xnonce1);
  bintostr(m_xnonce2, xnonc2, m_xnonce2sz);
  strcat(p_coinbase,xnonc2);
  strcat(p_coinbase,p_coinb2);

  //CDCSER.println("Coinbase:");
  //parprnt(p_coinb1);
  //parprnt(p_xnonce1);
  //parprnt(xnonc2);
  //parprnt(p_coinb2);
  //CDCSER.println("Assembled: "); CDCSER.println(p_coinbase);
}

/*
 * Construct 80-byte header from (ascii-to-binned) pool data and coinbase transaction
 * byte#  (int endian)
 * 0..3   LE           Version
 * 4..35  LE           Previous block hash
 * 36..67 BE           Merkle root
 * 68..71 LE           nTime
 * 72..75 LE           nBits
 * 76..80 ??           Nonce
 */
void Header_construct()
{
  uint8_t sha_merkle[64];
  uint8_t revbincoin[1024];
  uint8_t bincoinbase[1024];
  sha256_ctx ctx;
  int i;
  long tt;

    /* block #779626 header verification:
me:   000000202edbe5f59a32d725ca5ca404ce29acc3e5a83519ae4f05000000000000000000bfb41a94c9aa4718ae1cf1f87384a043447bc39c43878b07a0c0bfa84694f5fc465e0664a3890617bb57c201
real: 004061332edbe5f59a32d725ca5ca404ce29acc3e5a83519ae4f05000000000000000000526073d5c307cfac7ccaf76cce49d90edd39e291f53cbbc0a75bb48a40631715b95e0664a38906173005a83a
      so all seems to be in order..
   */


  // assemble coinbase transaction
  Header_makecoinbase();
  // make binary
  i = hexstr2bin(p_coinbase, bincoinbase);
  // double hash binary coinbase transaction
  DblHash(sha_merkle,bincoinbase,i);
  // double hash with merkles
  for(i=0;i<m_nmerkle;i++)
  {
    memcpy(&sha_merkle[32],m_merkle[i],32);
    DblHash(sha_merkle,sha_merkle,64);
  }
  // Construct binary header
  //
  // insert version
  memcpy_reverse(m_header,&m_version,4);
  // insert prevblockhash, endian swapped
  for(i=0;i<8;i++)
  {
    m_header[4+i*4] = m_prevblockhash[i*4+3];
    m_header[4+i*4+1] = m_prevblockhash[i*4+2];
    m_header[4+i*4+2] = m_prevblockhash[i*4+1];
    m_header[4+i*4+3] = m_prevblockhash[i*4];
  }
  // insert merkle root
  memcpy(&m_header[36],sha_merkle,32);
  // insert ntime, nbits, nonce
  memcpy_reverse(&m_header[68],m_ntime,4);
  memcpy_reverse(&m_header[72],m_nbits,4);
  memcpy(&m_header[76],&zeroes_4,4); // clear nonce
  //CDCSER.println("header:");
  //showresponse(m_header,80);
  //CDCSER.println();
}

/*
 * Create data for new job by incrementing ntime or xnonce2,
 * calls Header_construct to create a new binary block header
 */
void Header_nextjob()
{
  uint8_t sha_coinmerkle[32]; // will hold coinbase hash & merkle hash
  sha256_ctx ctx;
  int i;

  // increment ntime or xnonce2
  // incrementing ntime is not needed really with 'low' hashrates.
  if(ROLLNTIME & labs(millis()-m_Tntime)>1000) // roll nTime, should only happen upto 60x according to 'the internet',
  {                                // but most pools send new work in less than 60 seconds, so no need to limit it here ..
    inc_4bin(m_ntime); // increment nTime
    //memrnd(m_xnonce2,x_xnonce2sz); // and reset xnonce2
    m_Tntime = millis(); // time of last change of ntime
  }
  else
  {
    if(ROLLXN2) inc_nbin(m_xnonce2,m_xnonce2sz);
  }
  Header_construct();
}

/*
 * Convert pool data to binary,
 * assembles coinbase transaction
 * calls Header_construct to create a new binary block header
 */
void header_makebin()
{
  int i,len;

  // convert version to bin
  hexstr2bin(p_version, m_version);
  // convert prevblockhash to bin
  hexstr2bin(p_prevblockhash, m_prevblockhash);
  // convert nBits to bin
  hexstr2bin(p_nbits, m_nbits);
  nBits2Target();
  // convert ntime to bin
  hexstr2bin(p_ntime, m_ntime);
  // convert all merkle entries to bin
  i = 0;
  do
  {
    hexstrn2bin(p_partialmerkle+i*64, m_merkle[i], 32);
    i++;
  } while(p_partialmerkle[i*64]);
  m_nmerkle = i; // keep #merkle entries

  m_Tntime = millis(); // remember when this work was constructed
  Header_construct();
}

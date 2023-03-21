/*
 * Handle bitcoin mining pool comms without a json library as it is not needed for fixed order & format messages
 */
/*
 * Send
 * {"id": 5, "method": "mining.subscribe", "params": []}
 * Receive
 * {"result":[[["mining.notify","8a68e60d"]],"9ec57489",8],"id":5,"error":null}
 * {"params":[10000],"id":null,"method":"mining.set_difficulty"}
 * Send
 * {"params": ["1LUckyfck4y8veApUEVoA7DXWZNLeCaUnU", "password"], "id": 5, "method": "mining.authorize"}
 * Receive
 * {"params":["5eebeafb00195f62","33c30d18a2e5cb89d83350800ce781478217acd700010d070000000000000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3503a4ec0b000425bc166404ef599a170c","0a636b706f6f6c112f736f6c6f2e636b706f6f6c2e6f72672fffffffff03eb664e25000000001976a914d5a378670b6ed90a75ac5a8d30cd627e2ee6eca388acfae7c200000000001976a914f4cbe6c6bb3a8535c963169c22963d3a20e7686988ac0000000000000000266a24aa21a9ed87e13479a05be83b7ec3f1a2ea0bf6c3ecfff7a890c36fb506b685e5efdc3ac700000000",["fdfc70c747b718aedfdb85660ec25bd6334256720dccc759a3f31eae1ec85b23","0cbdd864a958eb66d43d6229e36fa46665a0c380ff91b31790582a7d71f4c70b","09e189fb16542811bc7894e521d487812750dcc7e250f73c7616bf73d924b520","8982837ce37c8ea6b16629a00d75f7d1af007a21c4040b4fd32259f29bce7834","01b37684df6a2866a878fec8728787d8a101860e41c5daeab52236cc4979495f","4b4ce09365465dcfeb1af147f6cf51f53a6557f4068c789cee81006d9a0e77fe","f29e84906324071dc363204c40b6e528c12aa5f22886457abee58a528eb28c9d","514a29b502ef5ced11922b1e3835c1403784a2757fa9f38bc2da73dfd50f2166","c560dd022023f5414add1af451d7ce762bdfac34bb3e3dfe2e80d9cfdf3a0104","6837042b249c3226459a48bc01eee9e1151f908d8073f470c0f497414b70f003","602ecff2f96e32c89602059134c2eb9088e28e72e035e1db7e3f5471cef7b1f7"],"20000000","17067681","6416bc25",true],"id":null,"method":"mining.notify"}
 */

#define mining_subscribe "{\"id\": 5, \"method\": \"mining.subscribe\", \"params\": []}\n"
#define parprnt(a) { CDCSER.print(#a); CDCSER.print(":"); CDCSER.println(a); }
void header_makebin(void); // in headerprep.h
int poolSuggestDifficulty(char *diff); // in this file
void MakeShareTarget(void);

char *jp,*bp;


// Json handling
void saveitem()
{
  char *p = bp;
  
  while(*jp != '"' && *jp != ',' && *jp != ']' && *jp != ':' && *jp != '}')
    *bp++ = *jp++;
  *bp++ = '\0';
  if(*jp == '"') jp++; // skip "
  if(*jp == ',') jp++; // skip ,
  CDCSER.println(p);
}

bool readitem()
{
  bool endd = false;
  char c = *jp;

  switch(c) // look at first character of item
  {
    case ':':
    case '{':
      jp++;   // discard '{' and ':'
      break;
    case '"':
      jp++;
      saveitem(); // quoted item: save entry without quotes
      break;
    case '[':
      *bp++ = c;
      *bp++ = '\0'; // save '[' as string
      jp++;
      break;
    case ']':
      *bp++ = c;
      *bp++ = '\0'; // save ']' as string
      jp++;
      if(*jp == ',') jp++;
      break;
    case '}':
      *bp++ = '\0'; // json string terminator-->ready
      endd = true;
      break;
    default:
      saveitem(); // if none of the above its a value/keyword, save it.
  }
  return endd;
}

/* jsonstringify:
 * converts json string in poolbf[] to sequence of null-terminated strings in jp[], every key/value/'[]' gets its own string. 
 * These strings do not include some characters from source (:{}")
 * example intput:
 * {"id":null,"method":"mining.set_difficulty","params":[8192]}
 * outputs:
 * id (NULL)
 * null (NULL)
 * method (NULL)
 * mining.set_difficulty (NULL)
 * params (NULL)
 * [ (NULL)
 * 8192 (NULL)
 * ] (NULL)
 * (NULL)
 */
void jsonstringify(char *poolbf)
{
  jp = poolbf;
  bp = decjsnbuf;
  while(!readitem()) ;
  int i = (int)bp-(int)decjsnbuf;
  //CDCSER.print("Stringify length ");
  //CDCSER.println(i);
}

// skip i lines, p points to character in first line to be skipped. Returns pointer to first char in the line after skipping
char *jsnskiplines(char *p,int i)
{
  if(i<= 0) return p;
  do
  {
    while(*p) p++;
    p++; // skip 0
    i--;
  } while(i);
  return p;
}

// pool comms

#define timeout 80000

int poolread(uint8_t *b) // read line from pool, return 1 for timeout, 2 for invalid data
{
  long t;
  int i;
  char tmout = 0;

  t = millis()+timeout;
  b[0] = 0;
  while(!poolclient.available()&& !tmout) // wait for data
  {
     if(millis()>t) return 1;
     delay(0);
  }
  t = millis()+timeout;
  i = 0;
  do
  {
    b[i++] = poolclient.read();
    if(millis()>t) tmout = 1;
  } while ((i<JSONBUFFER_SZ) && (b[i-1] != '\n') && !tmout && poolclient.available() && (b[i-1] != 0));
  if(tmout || i >= JSONBUFFER_SZ) tmout = 2;
  else b[i] = 0;

  return tmout;
}
/*
 *  Handle incomming pool message
 *  Called whenever poolclient.available() == true in loop()
 */

int pool_message()
{
  uint8_t pool_data_rcv[JSONBUFFER_SZ];
  char method[20];
  char *p,*pm;
  int i,rv;
  
  CDCSER.println("Handling incomming pool message");
  rv = poolread(pool_data_rcv);
  delay(0);
  if(rv) { CDCSER.println("Error receiving from pool"); return 1;}
  //CDCSER.print("Received: ");
  //CDCSER.println((char *)pool_data_rcv);
  //delay(5);
  jsonstringify((char *)pool_data_rcv);
  //delay(5);
  //CDCSER.println("Looking for method");
  p = decjsnbuf;
  delay(0);
  while(strcmp(p,"method") && *p)
  {
    //CDCSER.print("Skip: ");
    //CDCSER.println(p);
    p = jsnskiplines(p,1); 
  }
  if(!*p)
  {
    p = decjsnbuf;
    delay(0);
    while(strcmp(p,"result") && *p)
    {
      //CDCSER.print("Skip: ");
      //CDCSER.println(p);
      p = jsnskiplines(p,1); 
    }
    if(*p) // 'result' found, get share acceptance
    {
      p = jsnskiplines(p,1);
      if(!strcmp(p,"true"))
        CDCSER.println("Share accepted");
      else
        CDCSER.println("Share rejected!");
      return 0;
    }
    CDCSER.println("Unhandled message from pool");
    return 1;
  }
  p = jsnskiplines(p,1);
  strcpy(method,p);
  CDCSER.print("Method found: ");
  CDCSER.println(method);
  delay(0);

  if(!strcmp(method,"mining.set_difficulty"))
  {
    CDCSER.println("Handling mining.set_difficulty");
    p = decjsnbuf;
    delay(0);
    while(strcmp(p,"params") && *p) { p = jsnskiplines(p,1); }
    if(!*p) { CDCSER.println("Invalid message from pool"); return 1;} // no valid message, discard
    p = jsnskiplines(p,2);
    strcpy(p_ShareDif,p);
    parprnt(p_ShareDif);
    MakeShareTarget();
  }
  if(!strcmp(method,"mining.notify"))
  {
    p = decjsnbuf;
    delay(0);
    while(strcmp(p,"params") && *p) { p = jsnskiplines(p,1); }
    if(!*p) { CDCSER.println("Invalid message from pool"); return 1;} // no valid message, discard
    CDCSER.println("Handling mining.notify");
    p = jsnskiplines(p,2);
    strcpy(p_Jobid,p);
    //parprnt(p_Jobid);
    p = jsnskiplines(p,1);
    strcpy(p_prevblockhash,p);
    //parprnt(p_prevblockhash);
    p = jsnskiplines(p,1);
    strcpy(p_coinb1,p);
    //parprnt(p_coinb1);
    p = jsnskiplines(p,1);
    strcpy(p_coinb2,p);
    //parprnt(p_coinb2);
    p = jsnskiplines(p,2);
    pm = p_partialmerkle;
    delay(0);
    // concatenate all merkles to one long string
    while(strcmp(p,"]"))
    {
      strcpy(pm,p);
      pm += 64;
      p = jsnskiplines(p,1);
    }
    *pm = 0;
    //parprnt(p_partialmerkle);
    p = jsnskiplines(p,1);
    strcpy(p_version,p);
    //parprnt(p_version);
    p = jsnskiplines(p,1);
    strcpy(p_nbits,p);
    //parprnt(p_nbits);
    p = jsnskiplines(p,1);
    strcpy(p_ntime,p);
    //parprnt(p_ntime);
    p = jsnskiplines(p,1);
    strcpy(p_clean,p);
    //parprnt(p_clean);
    delay(0);
    m_havework = 1; // flag to notify we have work data
  }
  return 0;
}

/*  Connect to pool
 *  assumes open connection to pool in poolclient, eg
 *  WiFiClient poolclient;
 *  poolclient.connect(POOL_URL, POOL_PORT);
 *  Called in setup()
 */
int poolConnect()
{
  uint8_t pool_data_rcv[3000];
  char *p;
  int i,rv;
  
  i = 0;
  // send mining.subscribe
  CDCSER.println("Sending subscribe:");
  CDCSER.println(mining_subscribe);
  poolclient.print(mining_subscribe);
  delay(10);
  // line 1
  rv = poolread(pool_data_rcv);
  if(rv) return rv;
  CDCSER.print("Received(1): ");
  CDCSER.println((char *)pool_data_rcv);
  jsonstringify((char *)pool_data_rcv);
  p = decjsnbuf;
  // look for mining notify (MUST be present)
  while(strcmp(p,"mining.notify") && *p) { CDCSER.print("Skip: "); CDCSER.println(p);  p = jsnskiplines(p,1); }
  if(!*p) { CDCSER.println("Invalid message from pool"); return 1;} // no valid message, discard
  p = jsnskiplines(p,1);
  strcpy(p_MSubscriptid,p); // not used!
  parprnt(p_MSubscriptid);
  p = jsnskiplines(p,3);
  strcpy(p_xnonce1,p);
  parprnt(p_xnonce1);
  p = jsnskiplines(p,1);
  strcpy(p_xnonce2sz,p);
  parprnt(p_xnonce2sz);

  // look for id (MUST be present)
  p = decjsnbuf;
  while(strcmp(p,"id") && *p) { CDCSER.print("Skip: "); CDCSER.println(p);  p = jsnskiplines(p,1); }
  if(!*p) { CDCSER.println("Invalid message from pool"); return 1;} // no valid message, discard
  p = jsnskiplines(p,1);
  strcpy(p_sessionid,p);
  parprnt(p_sessionid);
  // look for mining set difficulty (CAN be present in the mining subscribe response)
  p = decjsnbuf;
  while(strcmp(p,"mining.set_difficulty") && *p) { CDCSER.print("Skip: "); CDCSER.println(p);  p = jsnskiplines(p,1); }
  if(*p)
  {
    p = jsnskiplines(p,1);
    strcpy(p_ShareDif,p);
    parprnt(p_ShareDif);
    MakeShareTarget();
    poolclient.flush(); // see if this helps
  }
  else
  {  
 
    delay(50);
    // line 2
    if(poolclient.available())
    {
      pool_message();
    }
  }
  char sendstr[200];
  delay(500);
  sendstr[0] = 0;
  strcat(sendstr,"{\"params\": [\"");
  strcat(sendstr,miningaddr);
  if(strlen(poolworker))
  {
    strcat(sendstr,".");
    strcat(sendstr,poolworker);
  }
  strcat(sendstr,"\",\"");
  strcat(sendstr,miningpw);
  strcat(sendstr,"\"], \"id\": ");
  strcat(sendstr,"5"); // miner id
  strcat(sendstr,", \"method\": \"mining.authorize\"}\n");
  //CDCSER.println(sendstr);
  poolclient.print(sendstr);

  // init pool related stuff
  m_TicketId = 0;

  // suggest difficulty
  poolSuggestDifficulty(p_SuggestedDiff);
  //poolSuggestDifficulty("1");
  
  return 0;
}

//        payload = String("{\"params\": [\"") + ADDRESS + String("\", \"") + job_id + String("\", \"") + extranonce2 + String("\", \"") + ntime + String("\", \"") + nonce +String("\"], \"id\": 1, \"method\": \"mining.submit\"");
int submitted = 0;

int poolSubmit(char *xnonce2, char *tme, char *nonce, char *pooljob, char *tickid)
{
  char substr[200];
  int i;

  strcpy(substr,"");
  strcat(substr,"{\"params\": [\"");
  strcat(substr,miningaddr);
  if(strlen(poolworker))
  {
    strcat(substr,".");
    strcat(substr,poolworker);
  }
  strcat(substr,"\", \"");
  strcat(substr,pooljob);
  strcat(substr,"\", \"");
  strcat(substr,xnonce2);
  strcat(substr,"\", \"");
  strcat(substr,tme);
  strcat(substr,"\", \"");
  strcat(substr,nonce);
  strcat(substr,"\"], \"id\": ");
  strcat(substr,tickid);
  strcat(substr,", \"method\": \"mining.submit\"}\n");
  //CDCSER.println(substr);
  CDCSER.println("===================Submitting SHARE==================");
  poolclient.print(substr);
  return 0;
}

int poolSuggestDifficulty(char *diff)
{
  // {"id": 2, "method": "mining.suggest_difficulty", "params": [42]}
  char substr[100];

  strcpy(substr,"");
  strcat(substr,"{\"id\": ");
  strcat(substr,p_sessionid);
  strcat(substr,",\"method\": \"mining.suggest_difficulty\", \"params\": [");
  strcat(substr,diff);
  strcat(substr,"]}\n");
  CDCSER.print("Pool diff suggestion: "); CDCSER.println(substr);
  poolclient.print(substr);
  return 0;
}

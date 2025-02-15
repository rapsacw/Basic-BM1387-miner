# Basic-BM1387-miner
Basic miner for my standalone asic miner(s).<br>
Updated soon, see screenshot of new version<br>
<br>
<h2>What is it</h2><br>
- An arduino sketch that together with suitable hardware will solo mine bitcoin on solo.ckpool.org<br>
- very much alpha but working.<br>
- 'Easily' adapted for other hardware, newer versions will be more hardware dependent and use more libraries.<br>
<br>
<h2>Dependencies</h2><br>
- Freenove_WS2812_Lib_for_ESP32 for led<br>
- pt8211 library for dac (see my repositories)<br>
<br>
<h2>How to use</h2><br>
Fill in your data:<br>
<code>#define ap_ssid "YOUR_SSID"
#define ap_password "YOUR_WIRELESS_PW"
#define POOL_URL "solo.ckpool.org" // most other pools don't work (yet)
#define POOL_PORT 3333
#define miningaddr "YOUR_BITCOIN_ADDR"
#define miningpw ""
#define poolworker "" // change to "YOURWORKERNAME" if you want to see statistics per worker on solo.ckpool.org
</code><br>
<h2>'Features'</h2><br>
- The first submitted shares can be invalid as the suggested difficulty is applied immediately instead of starting at the next work.<br>
- The program does not check if the pool is still alive or not, and will not auto reconnect.<br>
<br>
<h2>'Proof'</h2><br>
<code>  {
   "workername": "1KgwWwBh7qGtcWJ9ZRNTUbVCR1L2qYkzcy.PT8211",
   "hashrate1m": "44G",
   "hashrate5m": "30.7G",
   "hashrate1hr": "27.8G",
   "hashrate1d": "12G",
   "hashrate7d": "2.13G",
   "lastshare": 1679393908,
   "shares": 312689,
   "bestshare": 1222391.852158078,
   "bestever": 1222391
  },
  {
   "workername": "1KgwWwBh7qGtcWJ9ZRNTUbVCR1L2qYkzcy.Pharaonis",
   "hashrate1m": "61.1G",
   "hashrate5m": "46.3G",
   "hashrate1hr": "40G",
   "hashrate1d": "11.8G",
   "hashrate7d": "1.96G",
   "lastshare": 1679393900,
   "shares": 283484,
   "bestshare": 319822.6929729503,
   "bestever": 319822
  }
</code><br>
Running 2 workers (Pharaonis, 2 asic versions, passive cooling) for a few hours at 29 & 39GH/s. Efficiency is around 11GHs/W.

# Basic-BM1387-miner
Basic miner for my standalone asic miner(s)<br>
<br>
<h2>What is it</h2><br>
- An arduino sketch that together with suitable hardware will solo mine bitcoin on solo.skpool.org<br>
- very much alpha but working<br>
<br>
<h2>Dependencies</h2><br>
- Freenove_WS2812_Lib_for_ESP32 for led<br>
- pt8211 library for dac (see my repositories)<br>
<br>
<h2>How to use</h2>
Fill in your data:<br>
<code>
#define ap_ssid "YOUR_SSID"
#define ap_password "YOUR_WIRELESS_PW"
#define POOL_URL "solo.ckpool.org" // most other pools don't work (yet)
#define POOL_PORT 3333
#define miningaddr "YOU_BITCOIN_ADDR"
#define miningpw ""
#define poolworker "" // change to "YOURWORKERNAME" if you want to see statistics per worker on solo.ckpool.org
</code>

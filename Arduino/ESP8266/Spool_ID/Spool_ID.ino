#include <SPI.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <LittleFS.h>
#include "src/includes.h"

// --- PN532 (Elechouse) ---
#include <PN532_SPI.h>
#include <PN532.h>

// --- Pins ---
#define SS_PIN 4          // D2 on Wemos D1 mini (PN532 SS)
#define SPK_PIN 16        // D0 (buzzer/speaker)

// --- PN532 objects ---
PN532_SPI pn532spi(SPI, SS_PIN);
PN532 nfc(pn532spi);

// --- MIFARE keys/UID ---
uint8_t keyA[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // default factory key A
uint8_t eKey[6];                                         // derived/encrypted key
uint8_t uid[7];                                          // card UID buffer
uint8_t uidLength = 0;

ESP8266WebServer webServer;
AES aes;
File upFile;
String upMsg;
MD5Builder md5;

IPAddress Server_IP(10, 1, 0, 1);
IPAddress Subnet_Mask(255, 255, 255, 0);
String spoolData = "AB1240276A210100100000FF016500000100000000000000";
String AP_SSID = "K2_RFID";
String AP_PASS = "password";
String WIFI_SSID = "";
String WIFI_PASS = "";
String WIFI_HOSTNAME = "k2.local";
String PRINTER_HOSTNAME = "";
bool encrypted = false;      // true when we had to use eKey to authenticate

// ---- forward decls ----
void handleIndex();
void handle404();
void handleConfig();
void handleConfigP();
void handleDb();
void handleDbUpdate();
void handleFwUpdate();
void updateFw();
void handleSpoolData();
void loadConfig();
String split(String str, String from, String to);
bool instr(String str, String search);
void createKey();

void setup() {
  LittleFS.begin();
  loadConfig();

  // SPI + PN532 init
  SPI.begin();                // SCK=MOSI=MISO per ESP8266 defaults
  nfc.begin();
  uint32_t ver = nfc.getFirmwareVersion();
  if (!ver) {
    // PN532 not found
    tone(SPK_PIN, 400, 600);
    delay(1200);
  } else {
    // put PN532 in normal reader mode
    nfc.SAMConfig();          // required for inListPassiveTarget (ISO14443A)
  }

  pinMode(SPK_PIN, OUTPUT);

  if (AP_SSID == "" || AP_PASS == "") {
    AP_SSID = "K2_RFID";
    AP_PASS = "password";
  }
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  WiFi.softAP(AP_SSID.c_str(), AP_PASS.c_str());
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);

  if (WIFI_SSID != "" && WIFI_PASS != "") {
    WiFi.setAutoConnect(true);
    WiFi.setAutoReconnect(true);
    WiFi.hostname(WIFI_HOSTNAME);
    WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());
    WiFi.waitForConnectResult();
  }
  if (WIFI_HOSTNAME != "") {
    String mdnsHost = WIFI_HOSTNAME;
    mdnsHost.replace(".local", "");
    MDNS.begin(mdnsHost.c_str());
  }

  webServer.on("/config", HTTP_GET, handleConfig);
  webServer.on("/index.html", HTTP_GET, handleIndex);
  webServer.on("/", HTTP_GET, handleIndex);
  webServer.on("/material_database.json", HTTP_GET, handleDb);
  webServer.on("/config", HTTP_POST, handleConfigP);
  webServer.on("/spooldata", HTTP_POST, handleSpoolData);
  webServer.on("/update.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() { handleFwUpdate(); });
  webServer.on("/updatedb.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() { handleDbUpdate(); });
  webServer.onNotFound(handle404);
  webServer.begin(80);
}

static bool authBlock(uint8_t block, const uint8_t* key) {
  // keyNumber: 0 = Key A, 1 = Key B
  return nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block, 0, (uint8_t*)key);
}

void loop() {
  webServer.handleClient();

  // Look for a new ISO14443A target (MIFARE Classic included)
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50)) {
    return;
  }

  encrypted = false;

  // Derive eKey from UID (same logic as your original createKey)
  createKey();

  // Try to authenticate the sector trailer (block 7 for sector 1) with default Key A
  const uint8_t* activeKey = keyA;
  if (!authBlock(7, keyA)) {
    // Try with derived key
    if (!authBlock(7, eKey)) {
      // Fail: beep twice and bail
      tone(SPK_PIN, 400, 150);
      delay(300);
      tone(SPK_PIN, 400, 150);
      delay(2000);
      return;
    }
    encrypted = true;
    activeKey = eKey;
  }

  // Write encrypted data to blocks 4,5,6 of sector 1
  // (Your original code AES-encrypts each 16-char chunk then writes)
  uint8_t blockID = 4;
  for (int i = 0; i < spoolData.length(); i += 16) {
    if (blockID >= 4 && blockID < 7) {
      char chunk[17] = {0};
      spoolData.substring(i, i + 16).toCharArray(chunk, 17);

      uint8_t inBuf[16];
      uint8_t encOut[16];
      for (int k = 0; k < 16; k++) inBuf[k] = static_cast<uint8_t>(chunk[k]);

      // Ensure we’re authenticated for the specific block before write
      if (!authBlock(blockID, activeKey)) {
        tone(SPK_PIN, 400, 300);
        delay(1200);
        return;
      }
      aes.encrypt(1, inBuf, encOut);
      nfc.mifareclassic_WriteDataBlock(blockID, encOut);
    }
    blockID++;
  }

  // If the card still uses factory keys, update trailer (block 7) to set our eKey as Key A and Key B
  if (!encrypted) {
    // we are already authenticated to block 7 with keyA
    uint8_t buffer[16];
    if (nfc.mifareclassic_ReadDataBlock(7, buffer)) {
      // Key A (bytes 0..5)
      for (int i = 0; i < 6; i++) buffer[i] = eKey[i];
      // bytes 6..9 = access bits + GPB (leave as-is)
      // Key B (bytes 10..15)
      for (int i = 0; i < 6; i++) buffer[10 + i] = eKey[i];

      // Write back the sector trailer
      // (Still authenticated with Key A; factory access bits allow updating)
      nfc.mifareclassic_WriteDataBlock(7, buffer);
    }
  }

  // Success beep
  tone(SPK_PIN, 1000, 200);
  delay(2000);
}

// --- derive eKey from UID the same way your original code did ---
void createKey() {
  uint8_t tmpUid16[16];
  int x = 0;
  for (int i = 0; i < 16; i++) {
    if (x >= uidLength) x = 0;
    tmpUid16[i] = uid[x++];
  }
  uint8_t out[16];
  aes.encrypt(0, tmpUid16, out);
  for (int i = 0; i < 6; i++) eKey[i] = out[i];
}

// --- your existing HTTP/FS helpers (unchanged) ---
void handleIndex() { webServer.send_P(200, "text/html", indexData); }
void handle404() { webServer.send(404, "text/plain", "Not Found"); }
void handleConfig() {
  String htmStr = AP_SSID + "|-|" + WIFI_SSID + "|-|" + WIFI_HOSTNAME + "|-|" + PRINTER_HOSTNAME;
  webServer.setContentLength(htmStr.length());
  webServer.send(200, "text/plain", htmStr);
}
void handleConfigP() {
  if (webServer.hasArg("ap_ssid") && webServer.hasArg("ap_pass") && webServer.hasArg("wifi_ssid") && webServer.hasArg("wifi_pass") && webServer.hasArg("wifi_host") && webServer.hasArg("printer_host")) {
    AP_SSID = webServer.arg("ap_ssid");
    if (!webServer.arg("ap_pass").equals("********")) AP_PASS = webServer.arg("ap_pass");
    WIFI_SSID = webServer.arg("wifi_ssid");
    if (!webServer.arg("wifi_pass").equals("********")) WIFI_PASS = webServer.arg("wifi_pass");
    WIFI_HOSTNAME = webServer.arg("wifi_host");
    PRINTER_HOSTNAME = webServer.arg("printer_host");
    File file = LittleFS.open("/config.ini", "w");
    if (file) {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
    delay(1000);
    ESP.restart();
  } else {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}
void handleDb() {
  File dataFile = LittleFS.open("/matdb.gz", "r");
  if (!dataFile) {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send_P(200, "application/json", material_database, sizeof(material_database));
  } else {
    webServer.streamFile(dataFile, "application/json");
    dataFile.close();
  }
}
void handleDbUpdate() {
  upMsg = "";
  if (webServer.uri() != "/updatedb.html") { upMsg = "Error"; return; }
  HTTPUpload &upload = webServer.upload();
  if (upload.filename != "material_database.json") { upMsg = "Invalid database file<br><br>" + upload.filename; return; }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/matdb.gz")) LittleFS.remove("/matdb.gz");
    upFile = LittleFS.open("/matdb.gz", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) upFile.write(upload.buf, upload.currentSize);
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) { upFile.close(); upMsg = "Database update complete, Rebooting"; }
  }
}
void handleFwUpdate() {
  upMsg = "";
  if (webServer.uri() != "/update.html") { upMsg = "Error"; return; }
  HTTPUpload &upload = webServer.upload();
  if (!upload.filename.endsWith(".bin")) { upMsg = "Invalid update file<br><br>" + upload.filename; return; }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/update.bin")) LittleFS.remove("/update.bin");
    upFile = LittleFS.open("/update.bin", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) upFile.write(upload.buf, upload.currentSize);
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) upFile.close();
    updateFw();
  }
}
void updateFw() {
  if (!LittleFS.exists("/update.bin")) { upMsg = "No update file found"; return; }
  File updateFile = LittleFS.open("/update.bin", "r");
  if (!updateFile) { upMsg = "Error opening update.bin"; return; }
  size_t updateSize = updateFile.size();
  if (updateSize == 0) { updateFile.close(); LittleFS.remove("/update.bin"); upMsg = "Error, file is invalid"; return; }
  md5.begin(); md5.addStream(updateFile, updateSize); md5.calculate();
  String md5Hash = md5.toString();
  updateFile.close(); updateFile = LittleFS.open("/update.bin", "r");
  if (!updateFile) { upMsg = "Error re-opening update.bin"; return; }
  uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
  if (!Update.begin(maxSketchSpace, U_FLASH)) { updateFile.close(); upMsg = "Update failed<br><br>Not Enough Space"; return; }
  int md5BufSize = md5Hash.length() + 1; char md5Buf[md5BufSize]; md5Hash.toCharArray(md5Buf, md5BufSize);
  Update.setMD5(md5Buf);
  while (updateFile.available()) {
    uint8_t ibuffer[1];
    updateFile.read((uint8_t *)ibuffer, 1);
    Update.write(ibuffer, sizeof(ibuffer));
  }
  updateFile.close(); LittleFS.remove("/update.bin");
  if (Update.end(true)) {
    String uHash = md5Hash.substring(0,10);
    String iHash = Update.md5String().substring(0,10);
    iHash.toUpperCase(); uHash.toUpperCase();
    upMsg = "Uploaded:&nbsp; " + uHash + "<br>Installed: " + iHash + "<br><br>Update complete, Rebooting.";
  } else {
    upMsg = "Update failed";
  }
}
void handleSpoolData() {
  if (webServer.hasArg("materialColor") && webServer.hasArg("materialType") && webServer.hasArg("materialWeight")) {
    String materialColor = webServer.arg("materialColor"); materialColor.replace("#", "");
    String filamentId = "1" + webServer.arg("materialType");     // material_database.json
    String vendorId = "0276";                                    // 0276 creality
    String color = "0" + materialColor;
    String filamentLen = GetMaterialLength(webServer.arg("materialWeight"));
    String serialNum = String(random(100000, 999999));
    String reserve = "000000";
    spoolData = "AB124" + vendorId + "A2" + filamentId + color + filamentLen + serialNum + reserve + "00000000";
    File file = LittleFS.open("/spool.ini", "w");
    if (file) { file.print(spoolData); file.close(); }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
  } else {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}
String GetMaterialLength(String materialWeight) {
  if (materialWeight == "1 KG")   return "0330";
  else if (materialWeight == "750 G") return "0247";
  else if (materialWeight == "600 G") return "0198";
  else if (materialWeight == "500 G") return "0165";
  else if (materialWeight == "250 G") return "0082";
  return "0330";
}
String errorMsg(int errnum) {
  if (errnum == UPDATE_ERROR_OK) return "No Error";
  else if (errnum == UPDATE_ERROR_WRITE) return "Flash Write Failed";
  else if (errnum == UPDATE_ERROR_ERASE) return "Flash Erase Failed";
  else if (errnum == UPDATE_ERROR_READ) return "Flash Read Failed";
  else if (errnum == UPDATE_ERROR_SPACE) return "Not Enough Space";
  else if (errnum == UPDATE_ERROR_SIZE) return "Bad Size Given";
  else if (errnum == UPDATE_ERROR_STREAM) return "Stream Read Timeout";
  else if (errnum == UPDATE_ERROR_MD5) return "MD5 Check Failed";
  else if (errnum == UPDATE_ERROR_MAGIC_BYTE) return "Magic byte is wrong, not 0xE9";
  else return "UNKNOWN";
}
void loadConfig() {
  if (LittleFS.exists("/config.ini")) {
    File file = LittleFS.open("/config.ini", "r");
    if (file) {
      String iniData;
      while (file.available()) { char chnk = file.read(); iniData += chnk; }
      file.close();
      if (instr(iniData, "AP_SSID=")) { AP_SSID = split(iniData, "AP_SSID=", "\r\n"); AP_SSID.trim(); }
      if (instr(iniData, "AP_PASS=")) { AP_PASS = split(iniData, "AP_PASS=", "\r\n"); AP_PASS.trim(); }
      if (instr(iniData, "WIFI_SSID=")) { WIFI_SSID = split(iniData, "WIFI_SSID=", "\r\n"); WIFI_SSID.trim(); }
      if (instr(iniData, "WIFI_PASS=")) { WIFI_PASS = split(iniData, "WIFI_PASS=", "\r\n"); WIFI_PASS.trim(); }
      if (instr(iniData, "WIFI_HOST=")) { WIFI_HOSTNAME = split(iniData, "WIFI_HOST=", "\r\n"); WIFI_HOSTNAME.trim(); }
      if (instr(iniData, "PRINTER_HOST=")) { PRINTER_HOSTNAME = split(iniData, "PRINTER_HOST=", "\r\n"); PRINTER_HOSTNAME.trim(); }
    }
  } else {
    File file = LittleFS.open("/config.ini", "w");
    if (file) {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
  }
  if (LittleFS.exists("/spool.ini")) {
    File file = LittleFS.open("/spool.ini", "r");
    if (file) {
      String iniData;
      while (file.available()) { char chnk = file.read(); iniData += chnk; }
      file.close();
      spoolData = iniData;
    }
  } else {
    File file = LittleFS.open("/spool.ini", "w");
    if (file) { file.print(spoolData); file.close(); }
  }
}
String split(String str, String from, String to) {
  String tmpstr = str; tmpstr.toLowerCase();
  from.toLowerCase(); to.toLowerCase();
  int pos1 = tmpstr.indexOf(from);
  int pos2 = tmpstr.indexOf(to, pos1 + from.length());
  String retval = str.substring(pos1 + from.length(), pos2);
  return retval;
}
bool instr(String str, String search) {
  int result = str.indexOf(search);
  return result != -1;
}
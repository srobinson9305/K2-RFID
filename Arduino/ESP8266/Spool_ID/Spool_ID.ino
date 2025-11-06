#include <SPI.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <LittleFS.h>
#include "src/includes.h"  // provides AES aes; indexData/material_database

// PN532 (Elechouse) for SPI
#include <PN532_SPI.h>
#include <PN532.h>

// ---- Pins ----
#define SS_PIN 4           // D2 on Wemos D1 mini (PN532 SS)

// PN532 objects
PN532_SPI pn532spi(SPI, SS_PIN);
PN532 nfc(pn532spi);

// ---- MIFARE keys/UID ----
uint8_t keyA[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };  // factory key A
uint8_t eKey[6];                                      // derived key from UID (createKey)
uint8_t g_uid[7];
uint8_t g_uidLen = 0;

// ---- Web / FS / crypto ----
ESP8266WebServer webServer;
AES aes;
File upFile;
String upMsg;
MD5Builder md5;

// ---- Network (STA first; fallback to AP) ----
IPAddress Server_IP(10, 1, 0, 1);
IPAddress Subnet_Mask(255, 255, 255, 0);
String AP_SSID       = "K2_RFID";
String AP_PASS       = "password";

// Defaults per your home Wi-Fi (overrideable by /config)
String WIFI_SSID     = "Vista Way";
String WIFI_PASS     = "Gemini05";
String WIFI_HOSTNAME = "k2.local";

String PRINTER_HOSTNAME = "";

// ---- Spool payload (plaintext) ----
String spoolData = "AB1240276A210100100000FF016500000100000000000000";

// ---- State for verification/UI ----
bool   lastWriteVerified   = false;
String lastWriteUID        = "";
String lastWrittenSpool    = "";
unsigned long lastWriteMs  = 0;

// ---- Forward decls ----
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

// New helpers/endpoints
void createKey(const uint8_t* uid, uint8_t uidLen);
static bool authBlock(uint8_t block, const uint8_t* key);
static bool readBlock(uint8_t block, uint8_t* out16);
static bool writeBlock(uint8_t block, const uint8_t* data16);
static bool waitForCard(uint8_t* uid, uint8_t* uidLen, uint16_t timeoutMs);
static bool selectKeyForSector7(uint8_t* uid, uint8_t uidLen, const uint8_t** outKey);
static String hexOf(const uint8_t* buf, size_t len);
static String uidHex(const uint8_t* uid, uint8_t uidLen);
static String buildCipherHexFromSpool();     // expected encrypted hex for blocks 4..6
static void   writeMirrorPlaintext(const String& plain, const uint8_t* tryKey1, const uint8_t* tryKey2);
static bool   readMirrorPlaintext(String& outPlain, const uint8_t* tryKey1, const uint8_t* tryKey2);
static void   parseSpool(const String& s, String& brand, String& typeCode, String& amount, String& colorHex);

void handleVerifyJson();   // GET /verify.json
void handleReadJson();     // GET /read.json  (reads a card now and returns parsed fields)

// =================== SETUP ===================
void setup() {
  LittleFS.begin();
  loadConfig();  // may override defaults

  // --- PN532 init ---
  SPI.begin();
  nfc.begin();
  nfc.getFirmwareVersion(); // optional check; ignore 0 for headless bring-up
  nfc.SAMConfig();          // enable ISO14443A

  // --- Wi-Fi: try STA first ---
  WiFi.mode(WIFI_STA);
  WiFi.hostname(WIFI_HOSTNAME);
  WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());

  unsigned long t0 = millis();
  const unsigned long WIFI_TIMEOUT = 12000; // 12s
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < WIFI_TIMEOUT) {
    delay(200UL);
  }

  if (WiFi.status() == WL_CONNECTED) {
    if (WIFI_HOSTNAME != "") {
      String mdnsHost = WIFI_HOSTNAME;
      mdnsHost.replace(".local", "");
      MDNS.begin(mdnsHost.c_str());
    }
  } else {
    // Fallback: SoftAP
    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
    if (AP_SSID == "" || AP_PASS == "") {
      AP_SSID = "K2_RFID";
      AP_PASS = "password";
    }
    WiFi.softAP(AP_SSID.c_str(), AP_PASS.c_str());
    WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  }

  // --- Routes ---
  webServer.on("/config", HTTP_GET, handleConfig);
  webServer.on("/index.html", HTTP_GET, handleIndex);
  webServer.on("/", HTTP_GET, handleIndex);
  webServer.on("/material_database.json", HTTP_GET, handleDb);
  webServer.on("/config", HTTP_POST, handleConfigP);
  webServer.on("/spooldata", HTTP_POST, handleSpoolData);

  // OTA / DB upload
  webServer.on("/update.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000UL);
    ESP.restart();
  }, []() { handleFwUpdate(); });
  webServer.on("/updatedb.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000UL);
    ESP.restart();
  }, []() { handleDbUpdate(); });

  // New JSON endpoints
  webServer.on("/verify.json", HTTP_GET, handleVerifyJson);
  webServer.on("/read.json",   HTTP_GET, handleReadJson);

  webServer.onNotFound(handle404);
  webServer.begin(80);
}

// =================== LOOP ===================
void loop() {
  webServer.handleClient();

  // Auto-write when a card is presented (same behavior as before, but now verifies)
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, g_uid, &g_uidLen, 50)) {
    return;
  }

  const uint8_t* activeKey = nullptr;
  if (!selectKeyForSector7(g_uid, g_uidLen, &activeKey)) {
    // can't authenticate sector 1; ignore this card
    return;
  }

  // Assemble 3×16 bytes chunks from spoolData and encrypt them
  uint8_t expected[48] = {0};
  for (int i = 0; i < 3; i++) {
    char chunk[17] = {0};
    spoolData.substring(i * 16, i * 16 + 16).toCharArray(chunk, 17);
    uint8_t inBuf[16];
    for (int k = 0; k < 16; k++) inBuf[k] = (uint8_t)chunk[k];
    uint8_t encOut[16];
    aes.encrypt(1, inBuf, encOut);          // encrypt payload for blocks 4..6
    memcpy(&expected[i * 16], encOut, 16);
  }

  // Write blocks 4,5,6
  for (uint8_t block = 4; block <= 6; block++) {
    if (!authBlock(block, activeKey)) return;
    if (!writeBlock(block, &expected[(block - 4) * 16])) return;
  }

  // If sector trailer 7 was still factory key, we replace with eKey (both A & B)
  // We know selectKeyForSector7() tried keyA first. If that succeeded, encrypted==false.
  // Re-run the test: if auth with keyA works on 7, we update trailer to eKey.
  if (authBlock(7, keyA)) {
    uint8_t trailer[16];
    if (readBlock(7, trailer)) {
      for (int i = 0; i < 6; i++) trailer[i] = eKey[i];      // Key A
      // bytes 6..9: keep existing access bits/GPB
      for (int i = 0; i < 6; i++) trailer[10 + i] = eKey[i]; // Key B
      writeBlock(7, trailer);
    }
  }

  // Mirror plaintext into sector 2 (blocks 8..10) for UI reads (best effort)
  writeMirrorPlaintext(spoolData, keyA, eKey);

  // Record last write status for /verify.json
  lastWrittenSpool = spoolData;
  lastWriteUID     = uidHex(g_uid, g_uidLen);
  lastWriteMs      = millis();

  // Verify by reading back 4..6 and comparing to expected
  uint8_t rb[48] = {0};
  for (uint8_t block = 4; block <= 6; block++) {
    if (!authBlock(block, eKey) && !authBlock(block, keyA)) { lastWriteVerified = false; return; }
    if (!readBlock(block, &rb[(block - 4) * 16])) { lastWriteVerified = false; return; }
  }
  lastWriteVerified = (memcmp(rb, expected, 48) == 0);
}

// =================== RFID helpers ===================
void createKey(const uint8_t* uid, uint8_t uidLen) {
  // Derive eKey from UID using the same logic as your original createKey()
  uint8_t tmp[16]; int x = 0;
  for (int i = 0; i < 16; i++) {
    if (x >= uidLen) x = 0;
    tmp[i] = uid[x++];
  }
  uint8_t out[16];
  aes.encrypt(0, tmp, out);   // mode 0 per original code
  for (int i = 0; i < 6; i++) eKey[i] = out[i];
}

static bool authBlock(uint8_t block, const uint8_t* key) {
  return nfc.mifareclassic_AuthenticateBlock(g_uid, g_uidLen, block, 0, (uint8_t*)key);
}
static bool readBlock(uint8_t block, uint8_t* out16) {
  return nfc.mifareclassic_ReadDataBlock(block, out16);
}
static bool writeBlock(uint8_t block, const uint8_t* data16) {
  return nfc.mifareclassic_WriteDataBlock(block, (uint8_t*)data16);
}

static bool waitForCard(uint8_t* uid, uint8_t* uidLen, uint16_t timeoutMs) {
  unsigned long t0 = millis();
  do {
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uidLen, 10)) return true;
  } while (millis() - t0 < timeoutMs);
  return false;
}

static bool selectKeyForSector7(uint8_t* uid, uint8_t uidLen, const uint8_t** outKey) {
  createKey(uid, uidLen);
  // Try default Key A first
  if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 7, 0, keyA)) {
    *outKey = keyA; return true;
  }
  // Then derived key
  if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, 7, 0, eKey)) {
    *outKey = eKey; return true;
  }
  return false;
}

static String hexOf(const uint8_t* buf, size_t len) {
  static const char* hex = "0123456789ABCDEF";
  String s; s.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    s += hex[(buf[i] >> 4) & 0xF];
    s += hex[(buf[i]     ) & 0xF];
  }
  return s;
}
static String uidHex(const uint8_t* uid, uint8_t uidLen) {
  return hexOf(uid, uidLen);
}

static String buildCipherHexFromSpool() {
  uint8_t full[48] = {0};
  for (int i = 0; i < 3; i++) {
    char chunk[17] = {0};
    spoolData.substring(i * 16, i * 16 + 16).toCharArray(chunk, 17);
    uint8_t inBuf[16]; for (int k = 0; k < 16; k++) inBuf[k] = (uint8_t)chunk[k];
    uint8_t encOut[16]; aes.encrypt(1, inBuf, encOut);
    memcpy(&full[i * 16], encOut, 16);
  }
  return hexOf(full, 48);
}

// Write plaintext mirror to sector 2 (blocks 8..10) using tryKey1->tryKey2
static void writeMirrorPlaintext(const String& plain, const uint8_t* tryKey1, const uint8_t* tryKey2) {
  uint8_t block = 8;
  for (int i = 0; i < 3; i++, block++) {
    char chunk[17] = {0};
    plain.substring(i * 16, i * 16 + 16).toCharArray(chunk, 17);
    uint8_t out[16]; for (int k = 0; k < 16; k++) out[k] = (uint8_t)chunk[k];

    if (!authBlock(block, tryKey1) && !authBlock(block, tryKey2)) continue;
    writeBlock(block, out);
  }
}

// Read plaintext mirror from sector 2 into outPlain; returns true if valid
static bool readMirrorPlaintext(String& outPlain, const uint8_t* tryKey1, const uint8_t* tryKey2) {
  outPlain = "";
  uint8_t block = 8;
  uint8_t buf[16];
  for (int i = 0; i < 3; i++, block++) {
    if (!authBlock(block, tryKey1) && !authBlock(block, tryKey2)) return false;
    if (!readBlock(block, buf)) return false;
    for (int k = 0; k < 16; k++) {
      char c = (char)buf[k];
      if (c == '\0') break;
      outPlain += c;
    }
  }
  // Basic sanity: should start with "AB124" and be at least ~40 chars
  return outPlain.startsWith("AB124") && outPlain.length() >= 40;
}

// Parse fields we care about from the canonical spool string
static void parseSpool(const String& s, String& brand, String& typeCode, String& amount, String& colorHex) {
  // Layout (by your builder):
  // "AB124" (5)
  // vendorId (4)
  // "A2" (2)
  // filamentId (2)  -> "1" + materialType
  // color (7)       -> "0" + RRGGBB
  // filamentLen (4) -> "0330"/"0247"/...
  // serial (6)
  // reserve (6)
  // "00000000" (8)
  int idx = 0;
  idx += 5;
  brand = s.substring(idx, idx + 4); idx += 4;   // vendorId
  idx += 2;                                      // "A2"
  typeCode = s.substring(idx, idx + 2); idx += 2;
  String color7 = s.substring(idx, idx + 7); idx += 7;
  String len4   = s.substring(idx, idx + 4); idx += 4;
  // Map length code back to label
  if      (len4 == "0330") amount = "1 KG";
  else if (len4 == "0247") amount = "750 G";
  else if (len4 == "0198") amount = "600 G";
  else if (len4 == "0165") amount = "500 G";
  else if (len4 == "0082") amount = "250 G";
  else                     amount = "UNKNOWN";
  // Color
  if (color7.length() == 7 && color7[0] == '0') colorHex = "#" + color7.substring(1);
  else colorHex = "UNKNOWN";
}

// =================== HTTP handlers ===================
void handleIndex() { webServer.send_P(200, "text/html", indexData); }
void handle404()   { webServer.send(404, "text/plain", "Not Found"); }

void handleConfig() {
  String htmStr = AP_SSID + "|-|" + WIFI_SSID + "|-|" + WIFI_HOSTNAME + "|-|" + PRINTER_HOSTNAME;
  webServer.setContentLength(htmStr.length());
  webServer.send(200, "text/plain", htmStr);
}
void handleConfigP() {
  if (webServer.hasArg("ap_ssid") && webServer.hasArg("ap_pass") &&
      webServer.hasArg("wifi_ssid") && webServer.hasArg("wifi_pass") &&
      webServer.hasArg("wifi_host") && webServer.hasArg("printer_host")) {

    AP_SSID = webServer.arg("ap_ssid");
    if (!webServer.arg("ap_pass").equals("********")) AP_PASS = webServer.arg("ap_pass");
    WIFI_SSID = webServer.arg("wifi_ssid");
    if (!webServer.arg("wifi_pass").equals("********")) WIFI_PASS = webServer.arg("wifi_pass");
    WIFI_HOSTNAME    = webServer.arg("wifi_host");
    PRINTER_HOSTNAME = webServer.arg("printer_host");

    File file = LittleFS.open("/config.ini", "w");
    if (file) {
      file.print("\r\nAP_SSID=" + AP_SSID +
                 "\r\nAP_PASS=" + AP_PASS +
                 "\r\nWIFI_SSID=" + WIFI_SSID +
                 "\r\nWIFI_PASS=" + WIFI_PASS +
                 "\r\nWIFI_HOST=" + WIFI_HOSTNAME +
                 "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
    delay(1000UL);
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
  if (!updateFile) { upMsg = "Error"; return; }
  size_t updateSize = updateFile.size();
  if (updateSize == 0) { updateFile.close(); LittleFS.remove("/update.bin"); upMsg = "Error, file is invalid"; return; }

  md5.begin(); md5.addStream(updateFile, updateSize); md5.calculate();
  String md5Hash = md5.toString();
  updateFile.close();
  updateFile = LittleFS.open("/update.bin", "r");
  if (!updateFile) { upMsg = "Error"; return; }

  uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
  if (!Update.begin(maxSketchSpace, U_FLASH)) { updateFile.close(); upMsg = "Update failed<br><br>Not Enough Space"; return; }

  int md5BufSize = md5Hash.length() + 1; char md5Buf[md5BufSize]; md5Hash.toCharArray(md5Buf, md5BufSize);
  Update.setMD5(md5Buf);

  while (updateFile.available()) {
    uint8_t ibuffer[1];
    updateFile.read((uint8_t *)ibuffer, 1);
    Update.write(ibuffer, sizeof(ibuffer));
  }
  updateFile.close();
  LittleFS.remove("/update.bin");

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
    String filamentId = "1" + webServer.arg("materialType");  // application-level mapping is in your UI/db
    String vendorId   = "0276";                                // Creality
    String color      = "0" + materialColor;                   // 7 chars with leading 0
    String filamentLen = "";
    String w = webServer.arg("materialWeight");
    if      (w == "1 KG")   filamentLen = "0330";
    else if (w == "750 G")  filamentLen = "0247";
    else if (w == "600 G")  filamentLen = "0198";
    else if (w == "500 G")  filamentLen = "0165";
    else if (w == "250 G")  filamentLen = "0082";
    else                    filamentLen = "0330";

    String serialNum = String(random(100000, 999999));
    String reserve   = "000000";

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

// ---- New: write verification status ----
void handleVerifyJson() {
  String brand, typeCode, amount, color;
  parseSpool(lastWrittenSpool.length() ? lastWrittenSpool : spoolData, brand, typeCode, amount, color);

  String json = "{";
  json += "\"uid\":\"" + lastWriteUID + "\",";
  json += "\"verified\":" + String(lastWriteVerified ? "true" : "false") + ",";
  json += "\"age_ms\":" + String((lastWriteMs==0)?0:(millis()-lastWriteMs)) + ",";
  json += "\"spool\":{";
  json += "\"brand\":\"" + brand + "\",";
  json += "\"type_code\":\"" + typeCode + "\",";
  json += "\"amount\":\"" + amount + "\",";
  json += "\"color\":\"" + color + "\"";
  json += "},";
  json += "\"cipher_hex\":\"" + buildCipherHexFromSpool() + "\"";
  json += "}";
  webServer.send(200, "application/json", json);
}

// ---- New: read a card now and return parsed fields for UI ----
void handleReadJson() {
  uint8_t uid[7]; uint8_t uidLen = 0;
  if (!waitForCard(uid, &uidLen, 2000)) {
    webServer.send(200, "application/json", "{\"status\":\"no_card\"}");
    return;
  }

  const uint8_t* activeKey = nullptr;
  createKey(uid, uidLen);
  // Use sector 1 key for cipher blocks; but we’ll also try both keys for mirror sector
  if (!selectKeyForSector7(uid, uidLen, &activeKey)) {
    webServer.send(200, "application/json", "{\"status\":\"auth_failed\"}");
    return;
  }

  // Try reading mirror (plaintext) from sector 2 (blocks 8..10)
  String plain;
  bool mirrorOK = readMirrorPlaintext(plain, keyA, eKey);

  String json = "{";
  json += "\"status\":\"ok\",";
  json += "\"uid\":\"" + uidHex(uid, uidLen) + "\",";

  if (mirrorOK) {
    String brand, typeCode, amount, color;
    parseSpool(plain, brand, typeCode, amount, color);
    json += "\"spool\":{";
    json += "\"brand\":\"" + brand + "\",";
    json += "\"type_code\":\"" + typeCode + "\",";
    json += "\"amount\":\"" + amount + "\",";
    json += "\"color\":\"" + color + "\"";
    json += "},";
  } else {
    json += "\"spool\":null,";
  }

  // Always include raw cipher from blocks 4..6 (in case you want to cross-check on the UI)
  uint8_t rb[48] = {0};
  for (uint8_t block = 4; block <= 6; block++) {
    if (!authBlock(block, eKey) && !authBlock(block, keyA)) { json += "\"raw\":null}"; webServer.send(200, "application/json", json); return; }
    readBlock(block, &rb[(block - 4) * 16]);
  }
  json += "\"raw\":{";
  json += "\"cipher_hex\":\"" + hexOf(rb, 48) + "\",";
  json += "\"mirror\":"; json += mirrorOK ? "true" : "false";
  json += "}";
  json += "}";
  webServer.send(200, "application/json", json);
}

// =================== FS/Config helpers ===================
void loadConfig() {
  if (LittleFS.exists("/config.ini")) {
    File file = LittleFS.open("/config.ini", "r");
    if (file) {
      String iniData;
      while (file.available()) iniData += (char)file.read();
      file.close();
      if (instr(iniData, "AP_SSID="))       { AP_SSID = split(iniData, "AP_SSID=", "\r\n"); AP_SSID.trim(); }
      if (instr(iniData, "AP_PASS="))       { AP_PASS = split(iniData, "AP_PASS=", "\r\n"); AP_PASS.trim(); }
      if (instr(iniData, "WIFI_SSID="))     { WIFI_SSID = split(iniData, "WIFI_SSID=", "\r\n"); WIFI_SSID.trim(); }
      if (instr(iniData, "WIFI_PASS="))     { WIFI_PASS = split(iniData, "WIFI_PASS=", "\r\n"); WIFI_PASS.trim(); }
      if (instr(iniData, "WIFI_HOST="))     { WIFI_HOSTNAME = split(iniData, "WIFI_HOST=", "\r\n"); WIFI_HOSTNAME.trim(); }
      if (instr(iniData, "PRINTER_HOST="))  { PRINTER_HOSTNAME = split(iniData, "PRINTER_HOST=", "\r\n"); PRINTER_HOSTNAME.trim(); }
    }
  } else {
    // write defaults (includes your STA creds)
    File file = LittleFS.open("/config.ini", "w");
    if (file) {
      file.print("\r\nAP_SSID=" + AP_SSID +
                 "\r\nAP_PASS=" + AP_PASS +
                 "\r\nWIFI_SSID=" + WIFI_SSID +
                 "\r\nWIFI_PASS=" + WIFI_PASS +
                 "\r\nWIFI_HOST=" + WIFI_HOSTNAME +
                 "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
  }

  if (LittleFS.exists("/spool.ini")) {
    File file = LittleFS.open("/spool.ini", "r");
    if (file) {
      String iniData;
      while (file.available()) iniData += (char)file.read();
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
  return str.indexOf(search) != -1;
}
#include <iostream>
#include <fstream>
#include <time.h>
#include <iomanip>
using namespace std;
//Pause
void pause() {
  cout << "Operacja zakończona naciśnij dowolny klawisz aby wyjść: ";
  cin.get();
}
class GEA {
  // D_E_K_L_A_R_A_C_J_E	//
  //Deklaracje Zmiennych Szyfrowania
  unsigned char f;
  unsigned char b;
  unsigned char a;
  unsigned char h;
  unsigned char v;
  unsigned char q;
  unsigned char p;
  unsigned char rp;
  unsigned char sbox[256];
  unsigned char pbox[256];
  unsigned char pboxes[32][256];
  unsigned long long z[64];
  unsigned long long zt[32];
  unsigned long long rc[64];
  unsigned long long state[64][8][8];
  unsigned char bytes[8];
  unsigned char rt[8][8];
  unsigned char sboxes[32][256];
  unsigned char isboxes[32][256];
  unsigned char t[256];
  unsigned char tp[256];
  unsigned char pool[129][512];
  unsigned char keys[129][256];
  unsigned char y[512];
  unsigned char dt[256];
  unsigned char k[512];
  unsigned short ct[256];
  unsigned char iv[256];
  unsigned char cbc[256];
  unsigned char csum[256];
  unsigned char nf;
  unsigned long long bi;
  unsigned long long bl;
  unsigned long long zc;
  unsigned long long zr;
  unsigned long long xsf;
  char lblck[256];
  char text[256];
  char csumh[256];
  char hmac[256];
  char zeros[256];
  char ciphertext[256];
  char random[512];
  string message;
  string filename;
  string cfilename;
  string password;
  string password2;
  //Deklaracje Strumieni Plików Szyfrowania
  ifstream input;
  ofstream output;
  ofstream orandom;
  //Deklaracje Zmiennych Steganografii
  unsigned long long containercapacity;
  unsigned long long datacapacity;
  unsigned long long sbi;
  unsigned long long iters;
  unsigned short bs;
  unsigned short r;
  unsigned short w;
  unsigned short x;
  unsigned char n;
  unsigned char m;
  unsigned short u;
  unsigned char skey[32768];
  unsigned char sname[256];
  unsigned short ts[32768];
  unsigned short kts[32768];
  bool bits[8];
  unsigned long long contl;
  unsigned long long datal;
  unsigned long long datl;
  string cname;
  string dname;
  string siz;
  string tstr;
  //Deklaracje Strumieni Plików Steganografii
  fstream cont;
  fstream data;
  //Deklaracje Zmiennych Postępu
  unsigned short percent;
  unsigned long long prc;
  unsigned long long prg;
  // P_R_O_C_E_D_U_R_Y	O_G_Ó_L_N_E	//
  //PROCEDURY INTERFEJSU PROGRAMU
  //Procedura Postępu
  void progress() {
    if (zc == prg) {
      prg += prc;
      cout << "Ukończono: " << percent << "%" << endl;
      percent++;
    }
  }
  //Reset Stanu
  void resetstate() {
    b = 0;
    v = 0;
    r = 0;
    bs = 32768;
    xsf = 1;
    for (unsigned short s = 0; s < bs; s++)
      ts[s] = s;
    for (short i = 0; i < 256; i++)
      sbox[i] = i;
    for (short j = 0; j < 256; j++)
      pbox[j] = j;
    for (char t = 0; t < 64; t++) {
      for (char q = 0; q < 8; q++) {
        for (char r = 0; r < 8; r++) {
          state[t][q][r] = 1;
        }
      }
    }
    for (char j = 0; j < 64; j++)
      z[j] = 0;
    for (char j = 0; j < 32; j++)
      zt[j] = 0;
  }
  // P_R_Z_E_T_W_A_R_Z_A_N_I_E	H_A_S_Ł_A	//
  //Padding Hasła
  void paddingk() {
    system("stty -echo");
    cout << "Podaj Hasło: 512 B: ";
    getline(cin, password);
    cout << endl;
    cout << "Podaj Ponownie Hasło: 512 B: ";
    getline(cin, password2);
    cout << endl;
    if (password != password2) {
      cout << "Błąd: Hasła się nie zgadzają" << endl;
      paddingk();
    }
    unsigned short n = password.length();
    if (n > 512) {
      cout << "Błąd: Hasło za długie" << endl;
      paddingk();
    }
    for (short i = n; i < 512; i++)
      password.insert(n, "*");
    system("stty echo");
  }
  //Wstawianie Hasła
  void insk() {
    paddingk();
    for (short i = 0; i < 512; i++) {
      k[i] = password[i];
    }
    for (short h = 0; h < 512; h++) {
      y[h] = k[h];
    }
  }
  //Umieszczenie Soli
  void putsalt() {
    for (short p = 0; p < 512; p++) {
      y[p] ^= random[p];
    }
  }
  // K_R_Y_P_T_O_G_R_A_F_I_A	W_I_A_D_O_M_O_Ś_C_I	//
  //PROCEDURY WSTAWIANIA WIADOMOŚCI
  //Wstawianie Wiadomości
  void instm() {
    paddingm();
    for (short i = 0; i < 256; i++) {
      dt[i] = message[i];
    }
  }
  //Wstawianie Szyfrogramu Wiadomości
  void instcm() {
    cout << "Podaj Szyfrogram: 256 B: ";
    for (short i = 0; i < 256; i++)
      cin >> hex >> uppercase >> ct[i];
    cin.ignore();
    for (short l = 0; l < 256; l++)
      dt[l] = (char) ct[l];
  }
  //PROCEDURY WYŚWIETLANIA WIADOMOŚCI
  //Wyświetlanie Wiadomości
  void displayt() {
    unsigned char n;
    cout << endl;
    cout << "Wiadomość: " << endl << endl;
    n = dt[0];
    for (short i = 1; i < n + 1; i++)
      cout << dt[i];
    cout << endl;
  }
  //Wyświetlanie Szyfrogramu Wiadomości
  void displayc() {
    cout << endl;
    cout << "Szyfrogram: " << endl << endl;
    for (short i = 0; i < 256; i++)
      cout << setfill('0') << setw(2) << hex << uppercase << (short) dt[i] << " ";
    cout << endl;
  }
  //PROCEDURY SZYFROWANIA WIADOMOŚCI
  //Padding Wiadomości
  void paddingm() {
    unsigned short l;
    srand(time(0));
    cout << "Podaj Wiadomość: 255 B: ";
    getline(cin, message);
    unsigned char n = message.length();
    message.insert(0, 1, n);
    n = message.length();
    l = message.length();
    if (l > 255) {
      cout << "Błąd: Wiadomość za długa" << endl;
      paddingm();
    }
    for (short i = n; i < 256; i++) {
      message.insert(n, 1, rand());
    }
  }
  //Przygotowanie Szyfrowania Wiadomości
  void preparation() {
    insk();
    hashkey();
    hashing();
    gkeys();
    gsbox();
    igsbox();
    gpbox();
  }
  // Szyfrowanie Wiadomości
  void encryptm() {
    preparation();
    instm();
    geniv();
    putiv();
    encryption();
    displayc();
  }
  //Deszyfrowanie Wiadomości
  void decryptm() {
    preparation();
    instcm();
    decryption();
    geniv();
    putiv();
    displayt();
  }
  // P_R_Z_E_T_W_A_R_Z_A_N_I_E	P_L_I_K_Ó_W	//
  //PROCEDURY PADDINGU
  //Padding Szyfrowania
  void padding() {
    char c;
    srand(time(0));
    for (short j = 0; j < nf; j++) {
      input.get(c);
      lblck[j] = c;
    }
    for (short i = nf; i < 255; i++) {
      lblck[i] = rand();
    }
    lblck[255] = nf;
  }
  //Padding Sumy Kontrolnej
  void paddingh() {
    char c;
    for (short j = 0; j < nf; j++) {
      input.get(c);
      lblck[j] = c;
    }
    for (short i = nf; i < 256; i++) {
      lblck[i] = 0;
    }
  }
  //Zdejmowanie Paddingu
  void dpadding() {
    unsigned char ch;
    char c;
    ch = lblck[255];
    output.seekp(0, output.end);
    for (short p = 0; p < ch; p++) {
      c = lblck[p];
      output.put(c);
    }
  }
  //PROCEDURY ODCZYTU PLIKÓW
  //Odczyt Pliku
  void tread() {
    input.read(text, 256);
    for (short k = 0; k < 256; k++) {
      dt[k] = text[k];
    }
  }
  //Odczyt Zaszyfrowanego Pliku
  void cread() {
    input.read(ciphertext, 256);
    for (short k = 0; k < 256; k++) {
      dt[k] = ciphertext[k];
      cbc[k] = ciphertext[k];
    }
  }
  //Odczyt Soli
  void readsalt() {
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(0, input.beg);
    input.read(random, 512);
    input.close();
  }
  //Odczyt HMAC
  void readhmac() {
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(512, input.beg);
    input.read(hmac, 256);
    input.close();
  }
  //PROCEDURY ZAPISU PLIKÓW
  //Zapis Pliku
  void savet() {
    for (short p = 0; p < 256; p++) {
      text[p] = dt[p];
    }
    output.write(text, 256);
  }
  //Zapis Zaszyfrowanego Pliku
  void savec() {
    for (short p = 0; p < 256; p++) {
      ciphertext[p] = dt[p];
    }
    output.write(ciphertext, 256);
  }
  //Zapis Soli
  void gensalt() {
    initprng();
    output.open(cfilename.c_str(), ios::binary);
    if (!output.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    output.seekp(0, output.beg);
    for (short p = 0; p < 512; p++) {
      random[p] = y[p];
    }
    output.write(random, 512);
    output.write(zeros, 256);
    output.close();
  }
  //Zapis HMAC
  void savehmac() {
    output.open(cfilename.c_str(), ios::out | ios:: in | ios::binary);
    if (!output.good()) {
      cout << "Błąd: Nie można odczytać lub zapisać pliku " << endl;
      pause();
      exit(0);
    }
    output.seekp(512, output.beg);
    output.write(csumh, 256);
    output.close();
  }
  // K_R_Y_P_T_O_G_R_A_F_I_A	//
  //Prygotowanie Kryptografii
  void spreparation() {
    insk();
    putsalt();
    hashkey();
    hashing();
    gkeys();
    gsbox();
    igsbox();
    gpbox();
  }
  //Obliczanie Potęgi
  unsigned long long power(unsigned long long x, unsigned char p) {
    unsigned long long i = 1;
    for (short j = 1; j <= p; j++)
      i *= x;
    return i;
  }
  //PROCEDURY IV
  //Generowanie IV
  void geniv() {
    for (short p = 0; p < 256; p++)
      iv[p] = keys[128][p];
  }
  //Aktualizacja Szyfrowania IV
  void eupdateiv() {
    for (short p = 0; p < 256; p++)
      iv[p] = dt[p];
  }
  //Aktualizacja Deszyfrowania IV
  void dupdateiv() {
    for (short p = 0; p < 256; p++)
      iv[p] = cbc[p];
  }
  // Unieszczenie IV
  void putiv() {
    for (short p = 0; p < 256; p++)
      dt[p] ^= iv[p];
  }
  //PROCEDURY OSTATNIEGO BLOKU
  // Szyfrowanie Ostatniego Bloku
  void elblck() {
    padding();
    for (short i = 0; i < 256; i++)
      dt[i] = lblck[i];
    putiv();
    encryption();
    eupdateiv();
    savec();
  }
  // Deszyfrowanie Ostatniego Bloku
  void dlblck() {
    char c;
    for (short i = 0; i < 256; i++) {
      input.get(c);
      dt[i] = c;
    }
    decryption();
    putiv();
    dupdateiv();
    for (short j = 0; j < 256; j++) {
      lblck[j] = dt[j];
    }
    dpadding();
  }
  // Hash Ostatniego Bloku
  void hashlblck() {
    paddingh();
    for (short i = 0; i < 256; i++)
      dt[i] = lblck[i];
    genhash();
  }
  // HMAC Ostatniego Bloku
  void hmaclblck() {
    paddingh();
    for (short i = 0; i < 256; i++)
      dt[i] = lblck[i];
    genhmac();
  }
  //PROCEDURY	SPRAWDZANIA ROZMIARU
  //Sprawdzanie Rozmiaru Pliku
  void pchecksize() {
    unsigned long long length;
    input.open(filename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(0, input.end);
    length = input.tellg();
    input.seekg(0, input.beg);
    input.close();
    bi = (length / 256);
    bl = bi + 1;
    nf = (length - (256 * bi));
    prc = bl / 100;
  }
  // Sprawdzanie Rozmiaru Pliku Zaszyfrowanego
  void cchecksize() {
    unsigned long long length;
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(0, input.end);
    length = input.tellg();
    input.seekg(0, input.beg);
    input.close();
    bi = (length / 256);
    bl = bi + 1;
    nf = (length - (256 * bi));
    prc = (bi - 3) / 100;
  }
  //PROCEDURY UWIERZYTELNIANIA
  //Generowanie HMAC
  void ghmac() {
    percent = 0;
    prc = 0;
    prg = 0;
    cchecksize();
    resetstate();
    inith();
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(768, input.beg);
    for (zc = 0; zc < bi - 3; zc++) {
      cread();
      genhmac();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl;
    input.close();
  }
  //Weryfikacja HMAC
  void verifyhmac() {
    ghmac();
    for (short k = 0; k < 256; k++) {
      if (hmac[k] != csumh[k]) {
        cout << "Błąd: Nieprawidłowy HMAC: Plik uszkodzony lub nieprawidłowe hasło" << endl;
        pause();
        exit(0);
      }
    }
  }
  //PROCEDURY KONWERSJI LICZB
  //Konwersja 64 bit
  void to64() {
    for (char i = 0; i < 64; i++) {
      for (char j = 0; j < 8; j++)
        z[i] += power(256, j) * y[j + i * 8];
    }
  }
  //Konwersja 64 bit Tekstu Jawnego
  void to64t() {
    for (char i = 0; i < 32; i++) {
      for (char j = 0; j < 8; j++)
        zt[i] += power(256, j) * dt[j + i * 8];
    }
  }
  // Konwersja Bajtowa
  void tob() {
    for (char i = 0; i < 64; i++) {
      bytes[7] = (z[i] >> 56) & 0xFF;
      bytes[6] = (z[i] >> 48) & 0xFF;
      bytes[5] = (z[i] >> 40) & 0xFF;
      bytes[4] = (z[i] >> 32) & 0xFF;
      bytes[3] = (z[i] >> 24) & 0xFF;
      bytes[2] = (z[i] >> 16) & 0xFF;
      bytes[1] = (z[i] >> 8) & 0xFF;
      bytes[0] = z[i] & 0xFF;
      for (char j = 0; j < 8; j++)
        y[j + i * 8] = bytes[j];
    }
  }
  //Konwersja Bajtowa Tekstu Jawnego
  void tobt() {
    for (char i = 0; i < 32; i++) {
      bytes[7] = (zt[i] >> 56) & 0xFF;
      bytes[6] = (zt[i] >> 48) & 0xFF;
      bytes[5] = (zt[i] >> 40) & 0xFF;
      bytes[4] = (zt[i] >> 32) & 0xFF;
      bytes[3] = (zt[i] >> 24) & 0xFF;
      bytes[2] = (zt[i] >> 16) & 0xFF;
      bytes[1] = (zt[i] >> 8) & 0xFF;
      bytes[0] = zt[i] & 0xFF;
      for (char j = 0; j < 8; j++)
        dt[j + i * 8] = bytes[j];
    }
  }
  // ROTL
  unsigned long long rotl(unsigned long long x, unsigned char n) {
    unsigned long long y = (x << n) | (x >> (64 - n));
    return y;
  }
  // ROTR
  unsigned long long rotr(unsigned long long x, unsigned char n) {
    unsigned long long y = (x >> n) | (x << (64 - n));
    return y;
  }
  //PROCEDURY FUNKCJI HASH
  //Generator XORShift
  void xorshift() {
    if (xsf == 0)
      xsf = 1;
    for (short i = 0; i < 64; i++) {
      xsf ^= xsf >> 17;
      xsf ^= xsf << 29;
      xsf ^= xsf >> 31;
      rc[i] = xsf;
    }
    for (short j = 0; j < 8; j++) {
      for (short k = 0; k < 8; k++) {
        rt[j][k] = rc[8 * j + k] % 64;
      }
    }
  }
  //Rdzeń Fukcji Hash
  void sponge(unsigned long long q[64]) {
    for (char u = 0; u < 8; u++) {
      for (char w = 0; w < 8; w++) {
        state[0][u][w] ^= q[8 * u + w];
      }
    }
    for (char z = 0; z < 64; z++) {
      for (char y = 0; y < 8; y++) {
        for (char x = 0; x < 8; x++) {
          state[z][(y + 1) % 8][(x + 1) % 8] ^= state[z][y][x] ^
          state[z][(y + 1) % 8][x] ^ state[z][(y + 2) % 8][x] ^
          state[z][(y + 3) % 8][x] ^ state[z][(y + 4) % 8][x] ^
          state[z][(y + 5) % 8][x] ^ state[z][(y + 6) % 8][x] ^
          state[z][(y + 7) % 8][x];
          state[z][(y + 1) % 8][(x + 1) % 8] ^= rotl(state[z][y][x], rt[y][x]);
          state[z][(y + 1) % 8][(x + 1) % 8] ^= state[z][y][x] ^
          ((~state[z][(y + 1) % 8][(x + 1) % 8]) &
          state[z][(y + 2) % 8][(x + 2) % 8]);
          xsf ^= state[z][y][x];
          state[z][0][0] ^= rc[z];
          state[(z + 1) % 64][(y + 1) % 8][(x + 1) % 8] ^= state[z][y][x];
        }
      }
    }
    for (char s = 0; s < 8; s++) {
      for (char t = 0; t < 8; t++) {
        q[8 * s + t] ^= state[0][s][t];
      }
    }
  }
  //Funkcja Hash
  void hfunction() {
    unsigned long long tab[64];
    for (char i = 0; i < 64; i++) {
      tab[i] = z[i];
    }
    xorshift();
    sponge(tab);
    for (char j = 0; j < 64; j++) {
      z[j] = tab[j];
    }
  }
  //GENERATORY
  //Generowanie Podkluczy
  void gkeys() {
    for (short i = 0; i < 129; i++) {
      for (short j = 0; j < 256; j++) {
        keys[i][j] = (pool[i][j] ^ pool[i][511 - j]);
      }
    }
  }
  //Generowanie SBOX
  void gsbox() {
    for (short s = 0; s < 256; s++)
      t[s] = sbox[s];
    for (char d = 0; d < 32; d++) {
      for (short l = 0; l < 256; l++) {
        b += keys[d + 64][l] % 256;
        a = (t[l] + t[b]) % 256;
        b = (b + keys[d + 64][a]) % 256;
        h = t[l];
        t[l] = t[b];
        t[b] = h;
      }
      for (short w = 0; w < 256; w++)
        sboxes[d][w] = t[w];
    }
  }
  //Generowanie ISBOX
  void igsbox() {
    unsigned char c;
    for (char d = 0; d < 32; d++) {
      for (short l = 0; l < 256; l++) {
        c = sboxes[d][l];
        isboxes[d][c] = l;
      }
    }
  }
  //Generowanie PBOX
  void gpbox() {
    for (short s = 0; s < 256; s++)
      tp[s] = pbox[s];
    for (char d = 0; d < 32; d++) {
      for (short l = 0; l < 256; l++) {
        v += keys[d + 32][l] % 256;
        p = (tp[l] + tp[v]) % 256;
        v = (v + keys[d + 32][p]) % 256;
        q = tp[l];
        tp[l] = tp[v];
        tp[v] = q;
      }
      for (short w = 0; w < 256; w++)
        pboxes[d][w] = tp[w];
    }
  }
  //PROCEDURY HASH
  //Hash Puli
  void hashing() {
    to64();
    for (short i = 0; i < 129; i++) {
      hfunction();
      tob();
      for (short j = 0; j < 512; j++) {
        pool[i][j] = y[j];
      }
    }
  }
  //Hashowanie
  void hasher() {
    to64();
    hfunction();
    tob();
  }
  //Hashowanie Klucza
  void hashkey() {
    for (short q = 0; q < 1024; q++)
      hasher();
  }
  //PROCEDURY TRANSFORMACJI RUNDY SZYFROWANIA
  //Permutacja
  void permute() {
    unsigned char temp[256];
    for (short i = 0; i < 256; i++) {
      temp[i] = dt[i];
    }
    for (short j = 0; j < 256; j++) {
      dt[j] = temp[pboxes[f][j]];
    }
  }
  //Permutacja Odwrotna
  void ipermute() {
    unsigned char temp[256];
    for (short i = 0; i < 256; i++) {
      temp[i] = dt[i];
    }
    for (short j = 0; j < 256; j++) {
      dt[pboxes[f][j]] = temp[j];
    }
  }
  //Podstawienia
  void sboxing() {
    for (short i = 0; i < 256; i++)
      dt[i] = sboxes[f][dt[i]];
  }
  //Odwrotne Podstawienia
  void isboxing() {
    for (short i = 0; i < 256; i++)
      dt[i] = isboxes[f][dt[i]];
  }
  //Rotacja w Lewo
  void lrotating() {
    for (char i = 0; i < 32; i++)
      rotl(zt[i], keys[f + 96][i + (rp * 8)] % 64);
  }
  //Rotacja w Prawo
  void rrotating() {
    for (char i = 0; i < 32; i++)
      rotr(zt[i], keys[f + 96][i + (rp * 8)] % 64);
  }
  //XOR Fukcji Transformacji Liniowej
  void xoring() {
    for (char i = 0; i < 32; i++)
      zt[(i + 1) % 32] ^= zt[i] ^ zt[(i + 2) % 32];
  }
  //XOR Odwrotnej Fukcji Transformacji Liniowej
  void ixoring() {
    for (char i = 31; i >= 0; i--)
      zt[(i + 1) % 32] ^= zt[i] ^ zt[(i + 2) % 32];
  }
  //Funkcja Transformacji
  void tfunction() {
    lrotating();
    xoring();
  }
  //Odwrotna Funkcja Transformacji
  void itfunction() {
    ixoring();
    rrotating();
  }
  //Transformacja
  void transformation() {
    to64t();
    for (char i = 0; i < 8; i++) {
        rp = i;
        tfunction();
    }
    tobt();
    for (char j = 0; j < 32; j++)
      zt[j] = 0;
  }
  //Odwrotna Transformacja
  void itransformation() {
    to64t();
    for (char i = 0; i < 8; i++) {
        rp = i;
        itfunction();
    }
    tobt();
    for (char j = 0; j < 32; j++)
      zt[j] = 0;
  }
  //Dodawanie Klucza
  void keying() {
    for (short i = 0; i < 256; i++)
      dt[i] ^= keys[f][i];
  }
  //Runda Szyfrująca
  void round() {
    for (char rd = 0; rd < 32; rd++) {
      f = rd;
      permute();
      sboxing();
      transformation();
      keying();
    }
  }
  //Runda Deszyfrująca
  void iround() {
    for (char rd = 31; rd >= 0; rd--) {
      f = rd;
      keying();
      itransformation();
      isboxing();
      ipermute();
    }
  }
  //Szyfrowanie
  void encryption() {
    round();
  }
  //Deszyfrowanie
  void decryption() {
    iround();
  }
  //Szyfrowanie Pliku
  void erelease() {
    percent = 0;
    prc = 0;
    prg = 0;
    cout << "Podaj Nazwę Pliku: ";
    getline(cin, filename);
    cfilename = filename;
    cfilename.insert(cfilename.length(), ".gea");
    gensalt();
    spreparation();
    pchecksize();
    geniv();
    input.open(filename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    output.open(cfilename.c_str(), ios::binary | ios::app);
    if (!output.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    output.seekp(768, output.beg);
    cout << "Szyfrowanie..." << endl;
    for (zc = 0; zc < bi; zc++) {
      tread();
      putiv();
      encryption();
      eupdateiv();
      savec();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl;
    elblck();
    output.close();
    input.close();
    cout << "Generowanie HMAC..." << endl;
    ghmac();
    savehmac();
  }
  //Deszyfrowanie Pliku
  void drelease() {
    cout << "Podaj Nazwę Pliku: ";
    getline(cin, cfilename);
    filename = cfilename;
    filename.erase((filename.length() - 4), 4);
    readsalt();
    readhmac();
    spreparation();
    cout << "Weryfikowanie HMAC..." << endl;
    verifyhmac();
    percent = 0;
    prg = 0;
    geniv();
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    output.open(filename.c_str(), ios::binary | ios::app);
    if (!output.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(768, input.beg);
    cout << "Deszyfrowanie..." << endl;
    for (zc = 0; zc < bi - 4; zc++) {
      cread();
      decryption();
      putiv();
      dupdateiv();
      savet();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    dlblck();
    input.close();
    output.close();
  }
  // S_U_M_A 	K_O_N_T_R_O_L_N_A	//
  //PROCEDURY SUMY KONTROLNEJ
  //Inicjowanie Fukcji Hash
  void inith() {
    for (short i = 0; i < 512; i++) {
      y[i] = i;
    }
  }
  //Generowanie Bloku Hash
  void genhash() {
    for (short i = 0; i < 256; i++) {
      y[i] ^= dt[i];
      y[i + 256] ^= i;
    }
    hasher();
    for (short j = 0; j < 256; j++)
      csum[j] = y[j] ^ y[511 - j];
  }
  //Generowanie Bloku HMAC
  void genhmac() {
    for (short i = 0; i < 256; i++) {
      y[i] ^= dt[i];
      y[i + 256] ^= keys[128][i];
    }
    hasher();
    for (short j = 0; j < 256; j++) {
      csum[j] = y[j] ^ y[511 - j];
      csumh[j] = y[j] ^ y[511 - j];
    }
  }
  //Obliczanie Bloku Hash
  void chash() {
    percent = 0;
    prc = 0;
    prg = 0;
    inith();
    cout << "Podaj Nazwę Pliku: ";
    getline(cin, filename);
    pchecksize();
    input.open(filename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    cout << "Obliczanie Sumy Kontrolnej..." << endl;
    for (zc = 0; zc < bi; zc++) {
      tread();
      genhash();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl << endl;
    hashlblck();
    for (short j = 0; j < 256; j++)
      cout << setfill('0') << setw(2) << hex << uppercase << (short) csum[j];
    input.close();
    cout << endl;
  }
  //Obliczanie Bloku HMAC
  void chmac() {
    percent = 0;
    prc = 0;
    prg = 0;
    preparation();
    inith();
    cout << "Podaj Nazwę Pliku: ";
    getline(cin, filename);
    pchecksize();
    input.open(filename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    cout << "Obliczanie HMAC..." << endl;
    for (zc = 0; zc < bi; zc++) {
      tread();
      genhmac();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl << endl;
    hmaclblck();
    for (short j = 0; j < 256; j++)
      cout << setfill('0') << setw(2) << hex << uppercase << (short) csum[j];
    input.close();
    cout << endl;
  }
  // P_R_N_G	//
  //PROCEDURY PRNG
  //Inicjowanie PRNG
  void initprng() {
    srand(time(0));
    for (short i = 0; i < 512; i++) {
      y[i] = rand();
    }
  }
  //Generowanie PRNG
  void prng() {
    percent = 0;
    prc = 0;
    prg = 0;
    initprng();
    cout << "Ile Wygenerować?:[512 B Bloków]: ";
    cin >> zr;
    cin.ignore();
    while (zr <= 0) {
      cout << "Błąd! Zła Liczba! Spróbuj Ponownie!: ";
      cin >> zr;
    }
    prc = zr / 100;
    orandom.open("Random", ios::binary | ios::app);
    if (!orandom.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    cout << "Generowanie..." << endl;
    for (zc = 0; zc < zr; zc++) {
      hasher();
      for (short z = 0; z < 512; z++) {
        random[z] = y[z];
      }
      orandom.write(random, 512);
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    orandom.close();
  }
  // S_T_E_G_A_N_O_G_R_A_F_I_A	//
  //PROCEDURY NAZWY STEGANOGRAFII
  //Przygotowanie Nazwy
  void prepname() {
    siz.insert(0, "#");
    unsigned short n = siz.length();
    siz.insert(n, "#");
    tstr = siz + dname;
    n = tstr.length();
    tstr.insert(n, "#");
    paddingname();
    for (short i = 0; i < 256; i++)
      sname[i] = tstr[i];
  }
  //Padding Nazwy
  void paddingname() {
    srand(time(0));
    unsigned short n = tstr.length();
    for (short i = n; i < 256; i++) {
      tstr.insert(n, 1, rand());
    }
  }
  //Szyfrowanie Nazwy
  void encname() {
    for (short k = 0; k < 256; k++) {
      dt[k] = sname[k];
    }
    geniv();
    putiv();
    round();
    for (short k = 0; k < 256; k++) {
      sname[k] = dt[k];
    }
  }
  //Deszyfrowanie Nazwy
  void decname() {
    for (short k = 0; k < 256; k++) {
      dt[k] = sname[k];
    }
    iround();
    geniv();
    putiv();
    for (short k = 0; k < 256; k++) {
      sname[k] = dt[k];
    }
  }
  //Ukrywanie Nazwy
  void hidename() {
    unsigned char i = 0;
    char dc;
    char cc;
    unsigned short dp = 0;
    cont.open(cname.c_str(), ios::out | ios:: in | ios::binary);
    if (!cont.good()) {
      cout << "Błąd: Nie można odczytać lub zapisać pliku " << endl;
      pause();
      exit(0);
    }
    for (short j = 2048; j < 4096; j++) {
      if (i == 0) {
        dc = sname[dp];
        tobits(dc);
        dp++;
      }
      cont.seekp(j, cont.beg);
      cont.get(cc);
      if (((parity(cc) == 1) && (bits[i] == 0)) || ((parity(cc) == 0) && (bits[i] == 1)));
      else
      if ((parity(cc) == 1) && (bits[i] == 1)) {
        cc++;
        cont.seekp(j, cont.beg);
        cont.put(cc);
      } else
      if ((parity(cc) == 0) && (bits[i] == 0)) {
        cc--;
        cont.seekp(j, cont.beg);
        cont.put(cc);
      }
      i = (i + 1) % 8;
    }
    cont.close();
  }
  //Wyodrębnianie Nazwy
  void discovername() {
    u = 0;
    unsigned char i = 0;
    char cc;
    cont.open(cname.c_str(), ios:: in | ios::binary);
    if (!cont.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    for (short j = 2048; j < 4096; j++) {
      cont.seekg(j, cont.beg);
      cont.get(cc);
      if (parity(cc) == 1)
        bits[i] = 0;
      else
        bits[i] = 1;
      i = (i + 1) % 8;
      if (i == 0) {
        tobyten();
        u++;
      }
    }
    cont.close();
  }
  //Obróbka Nazwy
  void extrname() {
    unsigned short l = 0;
    stringstream ss;
    stringstream sn;
    if (sname[l] == '#') {
      l++;
      while (sname[l] != '#') {
        ss << sname[l];
        l++;
      }
    }
    siz = ss.str();
    if (sname[l] == '#') {
      l++;
      while (sname[l] != '#') {
        sn << sname[l];
        l++;
      }
    }
    dname = sn.str();
  }
  //Konwersja Nazwy na Bajt
  void tobyten() {
    for (char i = 0; i < 8; i++)
      m += power(2, i) * bits[i];
    sname[u] = m;
    m = 0;
  }
  //PROCEDURY SPRAWDZANIA ROZMIARU STEGANOGRAFII
  //Sprawdzanie Rozmiaru Kontenera
  void contchecksize() {
    cont.open(cname.c_str(), ios:: in | ios::binary);
    if (!cont.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    cont.seekg(0, cont.end);
    contl = cont.tellg();
    contl = contl - 4096;
    cont.seekg(0, cont.beg);
    cont.close();
    sbi = (contl / bs);
    containercapacity = (bs * sbi) / 8;
  }
  //Sprawdzanie Rozmiaru Danych
  void datachecksize() {
    stringstream ss;
    data.open(dname.c_str(), ios:: in | ios::binary);
    if (!data.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    data.seekg(0, data.end);
    datal = data.tellg() * 8;
    datacapacity = data.tellg();
    data.seekg(0, data.beg);
    data.close();
    ss << datal;
    siz = ss.str();
    prc = datal / 100;
    if (datacapacity > containercapacity) {
      cout << "Bład!: Plik Za Duży" << endl;
      pause();
      exit(0);
    }
  }
  //PROCEDURY STEGANOGRAFII
  //Pobieranie Bitów
  bool getbit(char byte, char position) {
    return (byte >> position) & 1;
  }
  //Konwersja na Bajt
  void tobyte() {
    for (char i = 0; i < 8; i++)
      n += power(2, i) * bits[i];
    data.put(n);
    n = 0;
  }
  //Konwersja na Bity
  void tobits(char c) {
    for (char i = 0; i < 8; i++) {
      bits[i] = getbit(c, i);
    }
  }
  //Sprawdzanie Parzystości
  bool parity(char c) {
    if ((c % 2) == 0)
      return 1;
    else
      return 0;
  }
  //Generowanie Klucza Steganografii
  void genskey() {
    for (short i = 0; i < 512; i++) {
      y[i] = password[i];
    }
    for (char z = 0; z < 64; z++) {
      hasher();
      for (short i = 0; i < 512; i++) {
        skey[i + (512 * z)] = y[i];
      }
    }
    for (unsigned short zz = 0; zz < bs; zz++) {
      kts[zz] = skey[zz];
    }
  }
  //Generowanie Permutacji Klucza Steganografii
  void gperm() {
    for (unsigned short l = 0; l < bs; l++) {
      r += kts[l] % bs;
      x = (ts[l] + ts[r]) % bs;
      r = (r + kts[x]) % bs;
      w = ts[l];
      ts[l] = ts[r];
      ts[r] = w;
    }
  }
  //Ukrywanie Pliku
  void hide() {
    percent = 0;
    prc = 0;
    prg = 0;
    iters = 0;
    unsigned char i = 0;
    unsigned long long j = 0;
    unsigned long long dp = 0;
    char dc;
    char cc;
    sterelease();
    resetstate();
    cout << "Podaj Hasło Steganografii: " << endl;
    preparation();
    genskey();
    gperm();
    cout << "Podaj Nazwę Kontenera: ";
    getline(cin, cname);
    contchecksize();
    dname = cfilename;
    datachecksize();
    prepname();
    encname();
    hidename();
    cout << "Pojemność Kontenera: " << containercapacity << " B" << endl;
    cont.open(cname.c_str(), ios::out | ios:: in | ios::binary);
    if (!cont.good()) {
      cout << "Błąd: Nie można odczytać lub zapisać pliku " << endl;
      pause();
      exit(0);
    }
    data.open(dname.c_str(), ios:: in | ios::binary);
    if (!data.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    zc = 0;
    percent = 0;
    prg = 0;
    cout << "Ukrywanie..." << endl;
    while (zc <= datal) {
      if (i == 0) {
        data.seekg(dp, data.beg);
        data.get(dc);
        tobits(dc);
        dp++;
      }
      cont.seekp((4096 + ((j * bs) + ts[iters])), cont.beg);
      cont.get(cc);
      if (((parity(cc) == 1) && (bits[i] == 0)) || ((parity(cc) == 0) && (bits[i] == 1)));
      else
      if ((parity(cc) == 1) && (bits[i] == 1)) {
        cc++;
        cont.seekp((4096 + ((j * bs) + ts[iters])), cont.beg);
        cont.put(cc);
      } else
      if ((parity(cc) == 0) && (bits[i] == 0)) {
        cc--;
        cont.seekp((4096 + ((j * bs) + ts[iters])), cont.beg);
        cont.put(cc);
      }
      i = (i + 1) % 8;
      j = (j + 1) % sbi;
      progress();
      zc++;
      if (j == 0) {
        iters++;
      }
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cont.close();
    data.close();
    remove(cfilename.c_str());
  }
  //Wyodrębnianie Pliku
  void discover() {
    zc = 0;
    percent = 0;
    prc = 0;
    prg = 0;
    iters = 0;
    unsigned char i = 0;
    unsigned long long j = 0;
    char cc;
    cout << "Podaj Hasło Steganografii: " << endl;
    preparation();
    genskey();
    gperm();
    cout << "Podaj Nazwę Kontenera: ";
    getline(cin, cname);
    contchecksize();
    discovername();
    decname();
    extrname();
    datal = atoi(siz.c_str());
    data.open(dname.c_str(), ios::out | ios::binary | ios::app);
    if (!data.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    cont.open(cname.c_str(), ios:: in | ios::binary);
    if (!cont.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    prc = datal / 100;
    percent = 0;
    prg = 0;
    cout << "Wyodrębnianie..." << endl;
    while (zc <= datal) {
      cont.seekg((4096 + ((j * bs) + ts[iters])), cont.beg);
      cont.get(cc);
      if (parity(cc) == 1)
        bits[i] = 0;
      else
        bits[i] = 1;
      i = (i + 1) % 8;
      j = (j + 1) % sbi;
      progress();
      zc++;
      if (i == 0)
        tobyte();
      if (j == 0) {
        iters++;
      }
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl;
    cont.close();
    data.close();
    resetstate();
    cout << "Podaj Hasło Deszyfrowania: " << endl;
    stdrelease();
    remove(cfilename.c_str());
  }
  //Szyfrowanie dla Steganografii
  void sterelease() {
    percent = 0;
    prc = 0;
    prg = 0;
    cout << "Podaj Nazwę Pliku Do Ukrycia: ";
    getline(cin, filename);
    cfilename = filename;
    cfilename.insert(cfilename.length(), ".gea");
    gensalt();
    cout << "Podaj Hasło Szyfrowania: " << endl;
    spreparation();
    pchecksize();
    geniv();
    input.open(filename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    output.open(cfilename.c_str(), ios::binary | ios::app);
    if (!output.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    output.seekp(768, output.beg);
    cout << "Szyfrowanie..." << endl;
    for (zc = 0; zc < bi; zc++) {
      tread();
      putiv();
      encryption();
      eupdateiv();
      savec();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    cout << endl;
    elblck();
    output.close();
    input.close();
    cout << "Generowanie HMAC..." << endl;
    ghmac();
    savehmac();
  }
  // Deszyfrowanie dla Steganografii
  void stdrelease() {
    cfilename = dname;
    filename = cfilename;
    filename.erase((filename.length() - 4), 4);
    readsalt();
    readhmac();
    spreparation();
    cout << "Weryfikowanie HMAC..." << endl;
    verifyhmac();
    percent = 0;
    prg = 0;
    geniv();
    input.open(cfilename.c_str(), ios::binary);
    if (!input.good()) {
      cout << "Błąd: Nie można odczytać pliku " << endl;
      pause();
      exit(0);
    }
    output.open(filename.c_str(), ios::binary | ios::app);
    if (!output.good()) {
      cout << "Błąd: Nie można zapisać pliku " << endl;
      pause();
      exit(0);
    }
    input.seekg(768, input.beg);
    cout << "Deszyfrowanie..." << endl;
    for (zc = 0; zc < bi - 4; zc++) {
      cread();
      decryption();
      putiv();
      dupdateiv();
      savet();
      progress();
    }
    cout << "Ukończono: " << 100 << "%" << endl;
    dlblck();
    input.close();
    output.close();
  }
  //PROCEDURY PUBLICZNE
  public:
    //WYZWALACZE KRYPTOGRAFII
    // Wyzwalanie Szyfrowania
    void encryptionrelease() {
      erelease();
    }
  // Wyzwalanie Deszyfrowania
  void decryptionrelease() {
    drelease();
  }
  // Wyzwalanie Szyfrowania Wiadomości
  void emrelease() {
    encryptm();
  }
  // Wyzwalanie Deszyfrowania Wiadomości
  void dmrelease() {
    decryptm();
  }
  // WYZWALACZE SUMY KONTROLNEJ
  // Wyzwalanie Obliczania Sumy Kontrolnej
  void hrelease() {
    chash();
  }
  // Wyzwalanie Obliczania HMAC
  void hmrelease() {
    chmac();
  }
  //Wyzwalanie PRNG
  void prelease() {
    prng();
  }
  //WYZWALACZE STEGANOGRAFII
  //Wyzwalanie Ukrywania
  void shrelease() {
    hide();
  }
  //Wyzwalanie Wyodrębniania
  void sdrelease() {
    discover();
  }
  //Konstruktor
  GEA() {
      b = 0;
      v = 0;
      r = 0;
      bs = 32768;
      xsf = 1;
      for (unsigned short s = 0; s < bs; s++)
        ts[s] = s;
      for (short i = 0; i < 256; i++)
        sbox[i] = i;
      for (short j = 0; j < 256; j++)
        pbox[j] = j;
      for (short j = 0; j < 256; j++)
        zeros[j] = 0;
      for (char t = 0; t < 64; t++) {
        for (char q = 0; q < 8; q++) {
          for (char r = 0; r < 8; r++) {
            state[t][q][r] = 1;
          }
        }
      }
      for (char j = 0; j < 64; j++)
        z[j] = 0;
      for (char j = 0; j < 32; j++)
        zt[j] = 0;
    }
    //Destruktor
    ~GEA() {}
};
//FUNKCJA GŁÓWNA PROGRAMU
int main() {
  system("clear");
  while (true) {
    cout << endl;
    cout << "+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+" << endl;
    cout << "|G|i|a|n|t| |E|n|c|r|y|p|t|i|o|n| |A|l|g|o|r|i|t|h|m|" << endl;
    cout << "+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+" << endl;
    cout << "                        MENU                         " << endl;
    cout << "                  1. Szyfrowanie Pliku               " << endl;
    cout << "                  2. Deszyfrowanie Pliku             " << endl;
    cout << "                  3. Suma Kontrolna                  " << endl;
    cout << "                  4. Kod Uwierzytelniający           " << endl;
    cout << "                  5. Generator Pseudolosowy          " << endl;
    cout << "                  6. Steganografia Ukrywanie         " << endl;
    cout << "                  7. Steganografia Wyodrębnianie     " << endl;
    cout << "                  8. Szyfrowanie Wiadomości          " << endl;
    cout << "                  9. Deszyfrowanie Wiadomości        " << endl;
    cout << "                  0. Wyjście                         " << endl;
    unsigned char ch;
    cout << "Wybór: ";
    cin >> ch;
    cin.ignore();
    switch (ch) {
    case '1':
      {
        cout << "Szyfrowanie Pliku: " << endl;
        GEA Enc;
        Enc.encryptionrelease();
        cout << endl;
        pause();
      }
      break;
    case '2':
      {
        cout << "Deszyfrowanie Pliku: " << endl;
        GEA Dec;
        Dec.decryptionrelease();
        cout << endl;
        pause();
      }
      break;
    case '3':
      {
        cout << "Suma Kontrolna: " << endl;
        GEA Hash;
        Hash.hrelease();
        cout << endl;
        pause();
      }
      break;
    case '4':
      {
        cout << "Kod Uwierzytelniający: " << endl;
        GEA HMAC;
        HMAC.hmrelease();
        cout << endl;
        pause();
      }
      break;
    case '5':
      {
        cout << "Generator Pseudolosowy: " << endl;
        GEA Prng;
        Prng.prelease();
        cout << endl;
        pause();
      }
      break;
    case '6':
      {
        cout << "Steganografia Ukrywanie: " << endl;
        GEA Stegano;
        Stegano.shrelease();
        cout << endl;
        pause();
      }
      break;
    case '7':
      {
        cout << "Steganografia Wyodrębnianie: " << endl;
        GEA Stegano;
        Stegano.sdrelease();
        cout << endl;
        pause();
      }
      break;
    case '8':
      {
        cout << "Szyfrowanie Wiadomości: " << endl;
        GEA SMSEnc;
        SMSEnc.emrelease();
        cout << endl;
        pause();
      }
      break;
    case '9':
      {
        cout << "Deszyfrowanie Wiadomości: " << endl;
        GEA SMSDec;
        SMSDec.dmrelease();
        cout << endl;
        pause();
      }
      break;
    case '0':
      {
        cout << "Koniec Programu" << endl;
        pause();
        exit(0);
      }
      break;
    default:
      {
        cout << "Błędny Wybór" << endl;
        pause();
      }
      system("clear");
    }
  }
  return 0;
}

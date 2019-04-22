#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <conio.h>
#include <time.h>

using namespace std;

void hidecursor()
{
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO info;
    info.dwSize = 20;
    info.bVisible = FALSE;
    SetConsoleCursorInfo(consoleHandle, &info);
}

class G4096
{

    unsigned char f;
    unsigned char b;
    unsigned char a;
    unsigned char h;
    unsigned char v;
    unsigned char q;
    unsigned char p;
    unsigned char sbox [256];
    unsigned char pbox [256];
    unsigned char pboxes[32][2][256];
    unsigned char ct [2][256];
    unsigned long long z[2][64];
    unsigned long long state [64][8][8];
    unsigned char bytes[2][8];
    unsigned char sboxes[64][2][256];
    unsigned char isboxes[64][2][256];
    unsigned char t[2][256];
    unsigned char tp[2][256];
    unsigned char pool [225][2][512];
    unsigned char keys [225][2][256];
    unsigned char y [2][512];
    unsigned char dt [2][256];
    unsigned char k [2][512];
    unsigned char pt [2][256];

    unsigned char mask [2][256];
    unsigned char csum [512];

    long long bi;
    long long bl;
    long long nf;
    long long zc;

    char text [512];
    char ciphertext [512];
    char random [1024];

    string filename;
    string password;
    string password2;

    ifstream iptemp;
    ifstream ictemp;
    ifstream itemp;

    ofstream optemp;
    ofstream octemp;
    ofstream otemp;

    ofstream orandom;

    unsigned int containercapacity;
    unsigned int datacapacity;
    unsigned short sbi;
    unsigned short bs;
    unsigned short iters;
    unsigned short r;
    unsigned short w;
    unsigned short x;
    unsigned char n;
    unsigned char m;
    unsigned short u;
    unsigned char skey [65536];
    unsigned char sname [512];

    unsigned short ts [65535];
    bool bits[8];

    long long contl;
    long long datal;

    string cname;
    string dname;
    string siz;
    string tstr;

    fstream cont;
    fstream data;
    fstream stemp;

    void echo()
    {
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode | (ENABLE_ECHO_INPUT));
    }

    void noecho()
    {
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    }


    void paddingk()
    {
        cout<<"Insert Password: 1024 bytes: ";
        noecho();
        getline(cin,password);
        cout<<endl;
        cout<<"Retype password: 1024 bytes: ";
        getline(cin,password2);
        cout<<endl;
        short n=password.length();
        short n2=password2.length();
        for(short i=n; i<1024; i++)
            password.insert(n,"*");
        for(short j=n2; j<1024; j++)
            password2.insert(n2,"*");
        if ((password.compare(password2) != 0))
        {
            cout<<"Error: Passwords not match. Try again"<<endl;
            paddingk();
        }
        echo();
    }

    unsigned long long power(unsigned long long x, unsigned char p)
    {
        unsigned long long i = 1;
        for (short j = 1; j <= p; j++)
            i *= x;
        return i;
    }

    void getseed()
    {
        for (short j=0; j<2; j++)
        {
            for (short i=0; i<512; i++)

                y[j][i]=pool[225][j][i];
        }
    }

    void genmask()
    {

        hasher();

        for(short q=0; q<2; q++)
        {
            for(short p=0; p<256; p++)

                mask[q][p]=(y[q][p]^y[q][511-p]);
        }

    }

    void eputmask()
    {

        for(short q=0; q<2; q++)
        {
            for(short p=0; p<256; p++)

                pt[q][p]^=mask[q][p];
        }

    }

    void dputmask()
    {

        for(short q=0; q<2; q++)
        {
            for(short p=0; p<256; p++)

                dt[q][p]^=mask[q][p];
        }

    }

    void padding()
    {

        optemp.open("PTemp", ios::binary | ios::app);
        optemp.seekp(0,optemp.end);
        switch(nf)
        {
        case 511:
            optemp.put('1');

            break;
        case 510:
        {
            optemp.put('1');
            optemp.put('1');
        }
        break;
        default:
        {
            optemp.put('1');
            for(short i=nf; i<510; i++)
                optemp.put('0');
            optemp.put('1');
        }
        }

        optemp.close();
    }

    void dpadding()
    {
        char ch;
        long long n=1;
        long long length;

        iptemp.open("PTemp", ios::binary);

        iptemp.seekg(-1,iptemp.end);
        iptemp.get(ch);
        do
        {
            n++;
            iptemp.seekg(-n,iptemp.end);
            iptemp.get(ch);

        }

        while(ch=='0');

        length = iptemp.tellg();
        iptemp.seekg(0,iptemp.beg);
        n=0;
        otemp.open("Temp", ios::binary);

        while(n!=length-1)
        {
            iptemp.get(ch);
            otemp.put(ch);
            n++;
        }

        otemp.close();
        iptemp.close();
    }

    void pchecksize()
    {
        long long length;
        iptemp.open("PTemp", ios::binary);
        iptemp.seekg (0, iptemp.end);
        length = iptemp.tellg();
        iptemp.seekg (0, iptemp.beg);
        iptemp.close();
        bi=(length/512);
        bl=bi+1;
        nf=(length-(512*bi));
    }

    void sepchecksize()
    {
        long long length;
        iptemp.open(filename.c_str(), ios::binary);
        iptemp.seekg (0, iptemp.end);
        length = iptemp.tellg();
        iptemp.seekg (0, iptemp.beg);
        iptemp.close();
        bi=(length/512);
        bl=bi+1;
        nf=(length-(512*bi));
    }

    void cchecksize()
    {
        long long length;
        ictemp.open("CTemp", ios::binary);
        ictemp.seekg (0, ictemp.end);
        length = ictemp.tellg();
        ictemp.seekg (0, ictemp.beg);
        ictemp.close();
        bi=(length/512);
        bl=bi+1;
        nf=(length-(512*bi));
    }

    void dpcopyt()
    {
        filename.erase((filename.length()-3),3);
        CopyFile("Temp",filename.c_str(),0);
    }

    void ecopyt()
    {

        bool b=CopyFile(filename.c_str(),"PTemp",0);
        if (!b)
        {
            cout << "Error: " << GetLastError() << endl;
            system("pause");
            exit(0);

        }

    }

    void ecopyc()
    {
        filename.insert(filename.length(),".gea");
        CopyFile("CTemp",filename.c_str(),0);
    }

    void dcopyc()
    {
        bool b=CopyFile(filename.c_str(),"CTemp",0);
        if (!b)
        {
            cout << "Error: " << GetLastError() << endl;
            system("pause");
            exit(0);
        }
    }

    void tread()
    {
        iptemp.read(text,512);

        for(short k=0; k<256; k++)
        {
            pt[0][k]=text[k];
            pt[1][k]=text[256+k];
        }
    }

    void cread()
    {
        ictemp.read(ciphertext,512);

        for(short k=0; k<256; k++)
        {
            ct[0][k]=ciphertext[k];
            ct[1][k]=ciphertext[256+k];
        }
    }

    void insk()
    {
        paddingk();
        for (short i=0; i<512; i++)
        {
            k[0][i]=password[i];
            k[1][i]=password[512+i];
        }
        for(short j=0; j<2; j++)
        {
            for(short h=0; h<512; h++)
            {
                y[j][h]=k[j][h];
            }
        }
    }

    void inst()
    {

        for (short j=0; j<2; j++)
        {
            for (short i=0; i<256; i++)
                dt[j][i]=pt[j][i];
        }
    }

    void insc()
    {

        for(short j=0; j<2; j++)
        {
            for (short i=0; i<256; i++)
            {
                dt[j][i]=ct[j][i];
            }
        }

    }

    void to64()
    {
        for(short k=0; k<2; k++)
        {
            for(short i=0; i<64; i++)
            {
                for(short j=0; j<8; j++)
                    z[k][i]+=power(256,j)*y[k][j+i*8];
            }
        }
    }

    void tob()
    {
        for(short k=0; k<2; k++)
        {
            for(short i=0; i<64; i++)
            {
                bytes[k][7] = (z[k][i] >> 56) & 0xFF;
                bytes[k][6] = (z[k][i] >> 48) & 0xFF;
                bytes[k][5] = (z[k][i] >> 40) & 0xFF;
                bytes[k][4] = (z[k][i] >> 32) & 0xFF;
                bytes[k][3] = (z[k][i] >> 24) & 0xFF;
                bytes[k][2] = (z[k][i] >> 16) & 0xFF;
                bytes[k][1] = (z[k][i] >> 8) & 0xFF;
                bytes[k][0] = z[k][i] & 0xFF;

                for(short j=0; j<8; j++)
                    y[k][j+i*8]=bytes[k][j];
            }
        }
    }

    unsigned long long rot(unsigned long long x, unsigned char n)
    {
        unsigned long long  y = (x << n) | (x >> (64-n));
        return y;
    }

    void sponge(unsigned long long q[64])
    {

        const unsigned char rt[8][8]=
        {
            {0,8,16,24,32,40,48,56},
            {9,17,25,33,41,49,57,1},
            {18,26,34,42,50,58,2,10},
            {27,35,43,51,59,3,11,19},
            {36,44,52,60,4,12,20,28},
            {45,53,61,5,13,21,29,37},
            {54,62,6,14,22,30,38,46},
            {63,7,15,23,31,39,47,55}
        };

        for(short u=0; u<8; u++)
        {
            for(short w=0; w<8; w++)
            {
                state[0][u][w]^=q[8*u+w];
            }
        }

        for(short z=0; z<64;  z++)
        {

            for(short y=0; y<8; y++)
            {

                for(short x=0; x<8; x++)
                {
                    state[z][(y+1)%8][(x+1)%8]^=state[z][y][x]^state[z][(y+1)%8][x]^state[z][(y+2)%8][x]^state[z][(y+3)%8][x]^state[z][(y+4)%8][x]^state[z][(y+5)%8][x]^state[z][(y+6)%8][x]^state[z][(y+7)%8][x];
                    state[z][(y+1)%8][(x+1)%8]^=rot(state[z][y][x]^state[z][(y+2)%8][(x+2)%8],1);
                    state[z][(y+1)%8][(x+1)%8]^=rot(state[z][y][x],rt[y][x]);
                    state[z][(y+1)%8][(x+1)%8]^=~state[z][y][x] & state[z][(y+2)%8][(x+2)%8];
                    state[(z+1)%64][(y+1)%8][(x+1)%8]^=state[z][y][x];
                }
            }
        }

        for(short s=0; s<8; s++)
        {
            for(short t=0; t<8; t++)
            {
                q[8*s+t]^=state[0][s][t];
            }
        }
    }

    void hfunction()
    {
        unsigned long long tab1[64];
        unsigned long long tab2[64];


        for(short i=0; i<64; i++)
        {
            tab1[i]=z[0][i];
            tab2[i]=z[1][i];
        }

        sponge(tab1);
        sponge(tab2);

        for(short j=0; j<64; j++)
        {
            z[0][j]=tab1[j];
            z[1][j]=tab2[j];
        }

    }

    void gkeys()
    {
        for(short i=0; i<225; i++)
        {
            for(short k=0; k<2; k++)
            {
                for(short j=0; j<256; j++)
                {
                    keys[i][k][j]=(pool[i][k][j]^pool[i][k][511-j]);
                }
            }
        }
    }

    void gsbox()
    {
        for(short o=0; o<2; o++)
        {
            for(short s=0; s<256; s++)
                t[o][s]=sbox[s];
        }

        for(short d=0; d<64; d++)
        {
            for(short k=0; k<2; k++)
            {
                for (short l=0; l<256; l++)
                {
                    b+=keys[d+128][k][l]%256;
                    a=(t[k][l]+t[k][b])%256;
                    b=(b+keys[d+128][k][a])%256;
                    h=t[k][l];
                    t[k][l]=t[k][b];
                    t[k][b]=h;
                }
            }

            for(short y=0; y<2; y++)
            {
                for(short w=0; w<256; w++)
                    sboxes[d][y][w]=t[y][w];
            }
        }
    }

    void igsbox()
    {
        unsigned char c;

        for(short d=0; d<64; d++)
        {
            for(short k=0; k<2; k++)
            {
                for (short l=0; l<256; l++)
                {
                    c=sboxes[d][k][l];
                    isboxes[d][k][c]=l;
                }
            }
        }
    }

    void gpbox()
    {
        for(short o=0; o<2; o++)
        {
            for(short s=0; s<256; s++)
                tp[o][s]=pbox[s];
        }

        for(short d=0; d<32; d++)
        {
            for(short k=0; k<2; k++)
            {
                for (short l=0; l<256; l++)
                {
                    v+=keys[d+192][k][l]%256;
                    p=(tp[k][l]+tp[k][v])%256;
                    v=(v+keys[d+192][k][p])%256;
                    q=tp[k][l];
                    tp[k][l]=tp[k][v];
                    tp[k][v]=q;
                }
            }

            for(short y=0; y<2; y++)
            {
                for(short w=0; w<256; w++)
                    pboxes[d][y][w]=tp[y][w];
            }
        }
    }

    void hashing()
    {
        to64();
        for(short i=0; i<225; i++)
        {
            for(h=0; h<2; h++)
            {
                hfunction();
                tob();
                for(short j=0; j<512; j++)
                {
                    pool[i][h][j]=y[h][j];
                }
            }
        }
    }

    void hasher()
    {
        to64();
        hfunction();
        tob();
    }

    void permute()
    {
        unsigned char temp1 [256];
        unsigned char temp2 [256];

        for(short i=0; i<256; i++)
        {
            temp1[i]=dt[0][i];
            temp2[i]=dt[1][i];
        }

        for(short j=0; j<256; j++)
        {
            dt[0][j]=temp1[pboxes[f][1][j]];
            dt[1][j]=temp2[pboxes[f][0][j]];
        }
    }

    void ipermute()
    {
        unsigned char temp1 [256];
        unsigned char temp2 [256];

        for(short i=0; i<256; i++)
        {
            temp1[i]=dt[0][i];
            temp2[i]=dt[1][i];
        }

        for(short j=0; j<256; j++)
        {
            dt[0][pboxes[f][1][j]]=temp1[j];
            dt[1][pboxes[f][0][j]]=temp2[j];
        }
    }

    void preparation()
    {
        insk();
        hashing();
        gkeys();
        gsbox();
        igsbox();
        gpbox();
        getseed();
    }

    void sepreparation()
    {
        initprng();
        hashing();
        gkeys();
        gsbox();
        igsbox();
        gpbox();
        getseed();
    }

    void round()
    {
        for(short m=0; m<32; m++)
        {
            f=m;
            permute();
            for(short i=0; i<256; i++)
            {

                dt[0][i]=sboxes[m][1][dt[0][i]];
                dt[1][i]=sboxes[m][0][dt[1][i]];

                dt[0][i]=(dt[0][i] << keys[m][1][i]%8 | dt[0][i] >> 8-keys[m][1][i]%8);
                dt[1][i]=(dt[1][i] << keys[m][0][i]%8 | dt[1][i] >> 8-keys[m][0][i]%8);

                dt[0][i]^=keys[m+32][0][i];
                dt[1][i]^=keys[m+32][1][i];

                a=(dt[0][i]+dt[1][i]);
                b=(dt[0][i]+(2*dt[1][i]));
                dt[0][i]=a;
                dt[1][i]=b;

                dt[0][i]=sboxes[m+32][1][dt[0][i]];
                dt[1][i]=sboxes[m+32][0][dt[1][i]];

                dt[0][i]=(dt[0][i] << keys[m+64][1][i]%8 | dt[0][i] >> 8-keys[m+64][1][i]%8);
                dt[1][i]=(dt[1][i] << keys[m+64][0][i]%8 | dt[1][i] >> 8-keys[m+64][0][i]%8);

                dt[0][i]^=keys[m+96][1][i];
                dt[1][i]^=keys[m+96][0][i];
            }
        }
    }

    void iround()
    {
        for(short m=31; m>=0; m--)
        {
            f=m;
            for(short i=0; i<256; i++)
            {

                dt[1][i]^=keys[m+96][0][i];
                dt[0][i]^=keys[m+96][1][i];

                dt[1][i]=(dt[1][i] >> keys[m+64][0][i]%8 | dt[1][i] << 8-keys[m+64][0][i]%8);
                dt[0][i]=(dt[0][i] >> keys[m+64][1][i]%8 | dt[0][i] << 8-keys[m+64][1][i]%8);

                dt[1][i]=isboxes[m+32][0][dt[1][i]];
                dt[0][i]=isboxes[m+32][1][dt[0][i]];

                b=(dt[1][i]-dt[0][i]);
                a=((2*dt[0][i])-dt[1][i]);
                dt[1][i]=b;
                dt[0][i]=a;

                dt[0][i]^=keys[m+32][0][i];
                dt[1][i]^=keys[m+32][1][i];

                dt[1][i]=(dt[1][i] >> keys[m][0][i]%8 | dt[1][i] << 8-keys[m][0][i]%8);
                dt[0][i]=(dt[0][i] >> keys[m][1][i]%8 | dt[0][i] << 8-keys[m][1][i]%8);

                dt[1][i]=isboxes[m][0][dt[1][i]];
                dt[0][i]=isboxes[m][1][dt[0][i]];

            }
            ipermute();
        }
    }

    void encryption()
    {
        inst();
        round();
    }

    void decryption()
    {
        insc();
        iround();
    }


    void savec()
    {
        octemp.seekp(zc*512,octemp.beg);
        for(short p=0; p<256; p++)
        {
            ciphertext[p]=dt[0][p];
            ciphertext[p+256]=dt[1][p];
        }
        octemp.write(ciphertext,512);
    }

    void saved()
    {
        optemp.seekp(zc*512,optemp.beg);
        for(short p=0; p<256; p++)
        {
            ciphertext[p]=dt[0][p];
            ciphertext[p+256]=dt[1][p];
        }
        optemp.write(ciphertext,512);
    }

    void savet()
    {
        optemp.seekp(zc*512, optemp.beg);
        for(short p=0; p<256; p++)
        {
            text[p]=dt[0][p];
            text[p+256]=dt[1][p];
        }
        optemp.write(text,512);
    }

    void inith()
    {
        for(short j=0; j<2; j++)
        {
            for(short i=0; i<512; i++)
            {
                y[j][i]=i;
            }
        }
    }

    void genhash()
    {
        for(short i=0; i<256; i++)
        {
            y[0][i]^=pt[0][i];
            y[0][i+256]^=pt[1][i];
            y[1][i]^=i;
            y[1][i+256]^=i;
        }

        hasher();

        for(short j=0; j<512; j++)
            csum[j]=(y[0][j]^y[1][j]);
    }

    void genhmac()
    {
        for(short i=0; i<256; i++)
        {
            y[0][i]^=pt[0][i];
            y[0][i+256]^=pt[1][i];
            y[1][i]^=keys[225][0][i];
            y[1][i+256]^=keys[225][1][i];
        }

        hasher();

        for(short j=0; j<512; j++)
            csum[j]=(y[0][j]^y[1][j]);

    }

    void chash()
    {
        unsigned char c256 [256];
        unsigned char c128 [128];
        inith();
        cout<<"Enter Filename to Hash: ";
        getline(cin,filename);
        ecopyt();
        pchecksize();
        padding();
        iptemp.open("PTemp", ios::binary);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bl; zc++)
        {
            iptemp.seekg(zc*512, iptemp.beg);
            tread();
            genhash();
        }
        cout<<endl;

        for(short s=0; s<256; s++)
        {
            c256[s]=csum[s]^csum[511-s];
        }

        for(short s=0; s<128; s++)
        {
            c128[s]=c256[s]^c256[255-s];
        }

        for(short j=0; j<128; j++)
            cout<<hex<<uppercase<<(short)c128[j];
        iptemp.close();
        cout<<endl;
    }

    void chmac()
    {
        unsigned char c256 [256];
        unsigned char c128 [128];
        preparation();
        inith();
        cout<<"Enter Filename to HMAC: ";
        getline(cin,filename);

        ecopyt();
        pchecksize();
        padding();
        iptemp.open("PTemp", ios::binary);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bl; zc++)
        {
            iptemp.seekg(zc*512, iptemp.beg);
            tread();
            genhmac();
        }
        cout<<endl;

        for(short s=0; s<256; s++)
        {
            c256[s]=csum[s]^csum[511-s];
        }

        for(short s=0; s<128; s++)
        {
            c128[s]=c256[s]^c256[255-s];
        }

        for(short j=0; j<128; j++)
            cout<<hex<<uppercase<<(short)c128[j];
        iptemp.close();
        cout<<endl;
    }

    void initprng()
    {
        srand(time(0));
        for(short j=0; j<2; j++)
        {
            for(short i=0; i<512; i++)
            {
                y[j][i]=rand();
            }
        }
    }

    void prng()
    {
        int n;
        initprng();
        cout<<"How Many Random Data? [KB]: ";
        cin>>n;
        while(n<=0)
        {
            cout<<"Error! Invalid number! Try Again!: ";
            cin>>n;
        }
        cin.ignore();
        orandom.open("Random", ios::binary | ios::app);
        cout<<"Processing. Please Wait..."<<endl;
        for(short i=0; i<n; i++)
        {
            hasher();
            for(short z=0; z<512; z++)
            {
                random[z]=y[0][z];
                random[z+512]=y[1][z];

            }
            orandom.write(random,1024);
        }
        orandom.close();
    }

    void sepadding()
    {
        srand(time(0));
        char c;
        optemp.open(filename.c_str(), ios::binary | ios::app);
        optemp.seekp(0,optemp.end);
        switch(nf)
        {
        case 511:
            optemp.put(c=rand());

            break;
        case 510:
        {
            optemp.put(c=rand());
            optemp.put(c=rand());
        }
        break;
        default:
        {
            optemp.put(c=rand());
            for(short i=nf; i<510; i++)
                optemp.put(c=rand());
            optemp.put(c=rand());
        }
        }

        optemp.close();
    }

    void sedelete()
    {
        char ans;
        unsigned long long counter=0;
        unsigned long long datl;
        short iterations;
        string con;
        cout<<"This operation destroys files! Deleted data is unrecoverable!"<<endl;
        cout<<"Enter Filename to Delete: ";
        getline(cin,filename);
        cout<<"Are you sure?: Y/N"<<endl;
        ans=getch();
        if((ans=='Y') || (ans=='y'))
        {
            cout<<"Please type ERASE: ";
            cin>>con;
            if(con=="ERASE")
            {
                cout<<"How many iterations?: [1-32]: ";
                cin>>iterations;
                cin.ignore();
                if((iterations>0) && (iterations<33))
                {
                    sepreparation();
                    sepchecksize();
                    sepadding();
                    optemp.open(filename.c_str(), ios::binary | ios::in | ios::out);
                    optemp.seekp(0,optemp.end);
                    datl=optemp.tellp();
                    optemp.seekp(0,optemp.beg);
                    cout<<"Processing. Please Wait..."<<endl;
                    for(short z=0; z<iterations; z++)
                    {
                        for(zc=0; zc<bl; zc++)
                        {
                            genmask();
                            optemp.seekp(zc*512, optemp.beg);
                            tread();
                            eputmask();
                            encryption();
                            saved();
                        }
                    }
                    while (counter<=datl)
                    {
                        optemp.seekp(counter,optemp.beg);
                        optemp.put('\0');
                        counter++;
                    }

                    optemp.close();
                    remove(filename.c_str());
                }
                else
                {
                    system("pause");
                    exit(0);
                }
            }
            else
            {
                system("pause");
                exit(0);
            }
        }
        else if((ans=='N') || (ans=='n'))
        {
            system("pause");
            exit(0);
        }
        else
        {
            cout<<"Error!"<<endl;
            system("pause");
            exit(0);
        }
    }

    void prepname()
    {
        siz.insert(0,"#");
        short n=siz.length();
        siz.insert(n,"#");
        tstr=siz+dname;
        n=tstr.length();
        tstr.insert(n,"#");
        paddingname();
        for(short i=0; i<512; i++)
            sname[i]=tstr[i];

    }

    void paddingname()
    {
        short n=tstr.length();
        for(short i=n; i<512; i++)
            tstr.insert(n," ");
    }

    void encname()
    {
        for(short k=0; k<256; k++)
        {
            dt[0][k]=sname[k];
            dt[1][k]=sname[256+k];
        }

        round();

        for(short k=0; k<256; k++)
        {
            sname[k]=dt[0][k];
            sname[k+256]=dt[1][k];
        }
    }

    void decname()
    {
        for(short k=0; k<256; k++)
        {
            dt[0][k]=sname[k];
            dt[1][k]=sname[k+256];
        }

        iround();

        for(short k=0; k<256; k++)
        {
            sname[k]=dt[0][k];
            sname[k+256]=dt[1][k];
        }
    }

    void hidename()
    {
        short i=0;
        char dc;
        char cc;
        short dp=0;

        cont.open(cname.c_str(), ios::out | ios::in | ios::binary);
        for(int j=4096; j<8192; j++)
        {
            if(i==0)
            {
                dc=sname[dp];
                tobits(dc);
                dp++;
            }

            cont.seekp(j,cont.beg);
            cont.get(cc);

            if(((parity(cc)==1) && (bits[i]==0)) || ((parity(cc)==0) && (bits[i]==1)));
            else if((parity(cc)==1) && (bits[i]==1))
            {
                cc++;
                cont.seekp(j,cont.beg);
                cont.put(cc);
            }
            else if((parity(cc)==0) && (bits[i]==0))
            {
                cc--;
                cont.seekp(j,cont.beg);
                cont.put(cc);
            }
            i=(i+1)%8;
        }

        cont.close();
    }

    void discovername()
    {
        u=0;
        short i=0;
        char dc;
        char cc;
        short dp=0;

        cont.open(cname.c_str(), ios::in | ios::binary);
        for(int j=4096; j<8192; j++)
        {
            cont.seekg(j,cont.beg);
            cont.get(cc);

            if(parity(cc)==1)
                bits[i]=0;
            else
                bits[i]=1;

            i=(i+1)%8;

            if(i==0)
            {
                tobyten();
                u++;
            }

        }

        cont.close();

    }

    void extrname()
    {
        unsigned short l=0;
        stringstream ss;
        stringstream sn;

        if(sname[l]=='#')
        {
            l++;
            while(sname[l]!='#')
            {
                ss<<sname[l];
                l++;
            }

        }

        siz=ss.str();

        if(sname[l]=='#')
        {
            l++;
            while(sname[l]!='#')
            {
                sn<<sname[l];
                l++;
            }

        }
        dname=sn.str();
    }

    void contchecksize()
    {
        cont.open(cname.c_str(), ios::in | ios::binary);
        cont.seekg (0, cont.end);
        contl = cont.tellg();
        contl=contl-8192;
        cont.seekg (0, cont.beg);
        cont.close();
        sbi=(contl/bs);
        containercapacity=(bs*sbi)/8;

        if(contl>(power(bs,2)/2))
        {
            cout<<"Error! Container is to big"<<endl;
            system("pause");
            exit(0);
        }
    }

    void datachecksize()
    {
        stringstream ss;
        data.open(dname.c_str(), ios::in | ios::binary);
        data.seekg (0, data.end);
        datal = data.tellg()*8;
        datacapacity = data.tellg();
        data.seekg (0, data.beg);
        data.close();
        ss<<datal;
        siz=ss.str();
        if(datacapacity>containercapacity)
        {
            cout<<"Error! Data is too big"<<endl;
            system("pause");
            exit(0);
        }
    }

    void gperm()
    {
        for (unsigned short l=0; l<bs; l++)
        {
            r+=skey[l]%bs;
            x=(ts[l]+ts[r])%bs;
            r=(r+skey[x])%bs;
            w=ts[l];
            ts[l]=ts[r];
            ts[r]=w;
        }
    }

    bool getbit(char byte, char position)
    {
        return (byte >> position) & 1;
    }

    void tobyte()
    {
        for(short i=0; i<8; i++)
            n+=power(2,i)*bits[i];
        stemp.put(n);
        n=0;
    }

    void tobyten()
    {

        for(short i=0; i<8; i++)
            m+=power(2,i)*bits[i];
        sname[u]=m;
        m=0;
    }

    void tobits(char c)
    {
        for(char i=0; i<8; i++)
        {
            bits[i]=getbit(c,i);
        }
    }

    bool parity(char c)
    {
        if((c%2)==0)
            return 1;
        else
            return 0;
    }

    void genskey()
    {

        for (short i=0; i<512; i++)
        {
            y[0][i]=password[i];
            y[1][i]=password[i+512];
        }


        for(short z=0; z<64; z++)
        {
            hasher();
            for (short i=0; i<512; i++)
            {
                skey[i+(512*z)]=y[0][i];
                skey[i+(512*z)+512]=y[1][i];
            }

        }
    }

    void resetstate()
    {
        b=0;
        v=0;
        r=0;
        bs=65535;

        for(unsigned short s=0; s<bs; s++)
            ts[s]=s;

        for(short i=0; i<256; i++)
            sbox[i]=i;
        for(short j=0; j<256; j++)
            pbox[j]=j;

        for(short t=0; t<64; t++)
        {
            for(short q=0; q<8; q++)
            {
                for(short r=0; r<8; r++)
                {
                    state[t][q][r]=1;
                }
            }
        }

        for(short i=0; i<2; i++)
        {
            for(short j=0; j<64; j++)
                z[i][j]=0;
        }
    }

    void hide()
    {
        iters=0;
        unsigned short i=0;
        unsigned short j=0;
        unsigned int dp=0;
        unsigned int counter=0;
        char dc;
        char cc;
        sterelease();
        resetstate();
        cout<<"Inserting Steganography Password: "<<endl;
        preparation();
        genskey();
        gperm();
        cout<<"Insert Container Name: ";
        getline(cin, cname);
        contchecksize();
        dname=filename;
        datachecksize();
        prepname();
        encname();
        hidename();

        cout<<"Container Capacity: "<<containercapacity<<" Bytes"<<endl;

        cont.open(cname.c_str(), ios::out | ios::in | ios::binary);
        data.open(dname.c_str(), ios::in | ios::binary);
        cout<<"Processing. Please Wait..."<<endl;

        while(counter<=datal)
        {

            if(i==0)
            {
                data.seekg(dp,data.beg);
                data.get(dc);
                tobits(dc);
                dp++;
            }

            cont.seekp((8192+((j*bs)+ts[iters])),cont.beg);
            cont.get(cc);

            if(((parity(cc)==1) && (bits[i]==0)) || ((parity(cc)==0) && (bits[i]==1)));
            else if((parity(cc)==1) && (bits[i]==1))
            {
                cc++;
                cont.seekp((8192+((j*bs)+ts[iters])),cont.beg);
                cont.put(cc);
            }
            else if((parity(cc)==0) && (bits[i]==0))
            {
                cc--;
                cont.seekp((8192+((j*bs)+ts[iters])),cont.beg);
                cont.put(cc);
            }
            i=(i+1)%8;
            j=(j+1)%sbi;
            counter++;

            if(j==0)
            {
                iters++;
            }

        }

        cont.close();
        data.close();
        remove(dname.c_str());
    }

    void discover()
    {
        iters=0;
        unsigned short i=0;
        unsigned int dp=0;
        unsigned short j=0;
        unsigned int counter=0;
        char dc;
        char cc;
        cout<<"Inserting Steganography Password: "<<endl;
        preparation();
        genskey();
        gperm();
        cout<<"Insert Container Name: ";
        getline(cin, cname);
        contchecksize();
        discovername();
        decname();
        extrname();
        datal=atoi(siz.c_str());

        stemp.open("STemp", ios::out | ios::binary);
        cont.open(cname.c_str(), ios::in | ios::binary);
        cout<<"Processing. Please Wait..."<<endl;

        while(counter<=datal)
        {

            cont.seekg((8192+((j*bs)+ts[iters])),cont.beg);
            cont.get(cc);

            if(parity(cc)==1)
                bits[i]=0;
            else
                bits[i]=1;

            i=(i+1)%8;
            j=(j+1)%sbi;
            counter++;

            if(i==0)
                tobyte();

            if(j==0)
            {
                iters++;
            }
        }

        cont.close();
        stemp.close();
        saveres();
        resetstate();
        cout<<"Inserting Decryption Password: "<<endl;
        stdrelease();
        remove(dname.c_str());
    }

    void saveres()
    {
        char ch;
        unsigned int length;
        unsigned int n=0;
        stemp.open("STemp", ios::in | ios::binary);
        data.open(dname.c_str(), ios::out | ios::binary);
        stemp.seekg(0,stemp.end);
        length=stemp.tellg();
        stemp.seekg(0,stemp.beg);
        while(n!=length)
        {
            stemp.get(ch);
            data.put(ch);
            n++;
        }
        stemp.close();
        data.close();
    }

    void sterelease()
    {
        cout<<"Enter Filename to Hide: ";
        getline(cin,filename);
        ecopyt();
        cout<<"Inserting Encryption Password: "<<endl;
        preparation();
        pchecksize();
        padding();
        iptemp.open("PTemp", ios::binary);
        octemp.open("CTemp", ios::binary | ios::app);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bl; zc++)
        {
            genmask();
            iptemp.seekg(zc*512, iptemp.beg);
            tread();
            eputmask();
            encryption();
            savec();
        }
        octemp.close();
        iptemp.close();
        ecopyc();
    }

    void stdrelease()
    {
        filename=dname;
        dcopyc();
        preparation();
        cchecksize();
        ictemp.open("CTemp", ios::binary);
        optemp.open("PTemp", ios::binary | ios::app);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bi; zc++)
        {
            genmask();
            ictemp.seekg(zc*512,ictemp.beg);
            cread();
            decryption();
            dputmask();
            savet();
        }

        ictemp.close();
        optemp.close();
        dpadding();
        dpcopyt();
    }


public:

    void hrelease()
    {
        chash();
    }

    void sdelrelease()
    {
        sedelete();
    }

    void hmrelease()
    {
        chmac();
    }

    void prelease()
    {
        prng();
    }

    void erelease()
    {
        cout<<"Enter Filename to Encrypt: ";
        getline(cin,filename);
        ecopyt();
        preparation();
        pchecksize();
        padding();
        iptemp.open("PTemp", ios::binary);
        octemp.open("CTemp", ios::binary | ios::app);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bl; zc++)
        {
            genmask();
            iptemp.seekg(zc*512, iptemp.beg);
            tread();
            eputmask();
            encryption();
            savec();
        }
        octemp.close();
        iptemp.close();
        ecopyc();
    }

    void drelease()
    {
        cout<<"Enter Filename to Decrypt: ";
        getline(cin,filename);
        dcopyc();
        preparation();
        cchecksize();
        ictemp.open("CTemp", ios::binary);
        optemp.open("PTemp", ios::binary | ios::app);
        cout<<"Processing. Please Wait..."<<endl;
        for(zc=0; zc<bi; zc++)
        {
            genmask();
            ictemp.seekg(zc*512,ictemp.beg);
            cread();
            decryption();
            dputmask();
            savet();
        }

        ictemp.close();
        optemp.close();
        dpadding();
        dpcopyt();
    }

    void shrelease()
    {
        hide();
    }

    void sdrelease()
    {
        discover();
    }

    G4096()
    {
        b=0;
        v=0;
        r=0;
        bs=65535;

        for(unsigned short s=0; s<bs; s++)
            ts[s]=s;

        for(short i=0; i<256; i++)
            sbox[i]=i;
        for(short j=0; j<256; j++)
            pbox[j]=j;

        for(short t=0; t<64; t++)
        {
            for(short q=0; q<8; q++)
            {
                for(short r=0; r<8; r++)
                {
                    state[t][q][r]=1;
                }
            }
        }

        for(short i=0; i<2; i++)
        {
            for(short j=0; j<64; j++)
                z[i][j]=0;
        }
        remove("Temp");
        remove("CTemp");
        remove("PTemp");
        remove("STemp");
    }

    ~G4096()
    {
        remove("Temp");
        remove("CTemp");
        remove("PTemp");
        remove("STemp");
    }

};

int main()
{
    hidecursor();
    system("cls");
    while(true)
    {
        cout<<endl;
        cout<<"+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+"<<endl;
        cout<<"|G|i|a|n|t| |E|n|c|r|y|p|t|i|o|n| |A|l|g|o|r|i|t|h|m|"<<endl;
        cout<<"+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+"<<endl;

        cout<<"                        MENU                         "<<endl;
        cout<<"                  1. Encryption                      "<<endl;
        cout<<"                  2. Decryption                      "<<endl;
        cout<<"                  3. Hash                            "<<endl;
        cout<<"                  4. HMAC                            "<<endl;
        cout<<"                  5. PRNG                            "<<endl;
        cout<<"                  6. Steganography Hide              "<<endl;
        cout<<"                  7. Steganography Discover          "<<endl;
        cout<<"                  8. Secure Delete                   "<<endl;
        cout<<"                  0. Exit                            "<<endl;

        unsigned char ch;
        cout<<"Choice : ";
        ch=getch();
        switch(ch)
        {
        case '1':
        {
            cout<<"Encryption: "<<endl;
            G4096 Enc;
            Enc.erelease();
            cout<<endl;
            system("pause");
        }
        break;
        case '2':
        {
            cout<<"Decryption: "<<endl;
            G4096 Dec;
            Dec.drelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '3':
        {
            cout<<"Hash: "<<endl;
            G4096 Hash;
            Hash.hrelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '4':
        {
            cout<<"HMAC: "<<endl;
            G4096 HMAC;
            HMAC.hmrelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '5':
        {
            cout<<"PRNG: "<<endl;
            G4096 Prng;
            Prng.prelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '6':
        {
            cout<<"Steganography Hide: "<<endl;
            G4096 Stegano;
            Stegano.shrelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '7':
        {
            cout<<"Steganography Discover: "<<endl;
            G4096 Stegano;
            Stegano.sdrelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '8':
        {
            cout<<"Secure Delete: "<<endl;
            G4096 Sedelete;
            Sedelete.sdelrelease();
            cout<<endl;
            system("pause");
        }
        break;

        case '0':
            cout<<"Program End"<<endl;
            system("pause");
            exit(0);
            break;
        default:
            cout<<"Error!"<<endl;
            system("pause");
        }
        system("cls");
    }

    return 0;
}

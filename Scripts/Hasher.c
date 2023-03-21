#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <wchar.h>

int* HashSpider( char* String, int* Length )
{
    long	Hash = 5381;
    char*	Ptr  = String;

    do
    {
        char character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (long) ( Ptr - (char*)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( 1 );

    return Hash;
}
void ToUpperString(char * temp) {
  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = toupper((unsigned char) *s);
    s++;
  }
}

unsigned int crc32b(const char* str) {

  #define SEED        0xEDB88320
  #define RANGE       0x1E
  unsigned int    byte    = 0x0,
              mask    = 0x0,
              crc     = 0xFFFFFFFF;
  int         i       = 0x0,
              j       = 0x0;

  while (str[i] != 0) {
    byte    = str[i];
    crc     = crc ^ byte;

    for (j = 7; j >= 0; j--) {
        mask    = -1 * (crc & 1);
        crc     = (crc >> 1) ^ (SEED & mask);
    }

    i++;
  }
  return ~crc;
}

int main(int argc, char** argv) 
{
  if (argc < 2)
    return 0;

  printf("\n[+] For HellHall's NTAPI\n");
  printf("[+] NTAPI (Case sensitive) %s ==> 0x%llx\n\n", argv[1], crc32b( (char*)argv[1] )); 


  ToUpperString(argv[1]);
  printf("\n[+] For C5pider's Shellcode Template\n");
  printf("[+] Function %s ==> 0x%x\n", argv[1], HashSpider( argv[1], strlen(argv[1]) )); 

  // Allocate memory for the wide string
  char *str = argv[1];
  size_t len = mbstowcs(NULL, str, 0);
  wchar_t *wcstr = (wchar_t*) malloc((len + 1) * sizeof(wchar_t));

  // Convert the string to a wide string
  mbstowcs(wcstr, str, len);

  // convert the wide string to little-endian UTF-16 wide string
  len = wcslen(wcstr) * 2;
  char *lestr = (char*) malloc((len + 2) * sizeof(char));
  for (int i = 0; i < wcslen(wcstr); i++) {
      lestr[i*2] = wcstr[i] & 0xFF;
      lestr[i*2+1] = (wcstr[i] >> 8) & 0xFF;
  }
  lestr[len] = '\0';
  lestr[len+1] = '\0';

  printf("[+] Module %s ==> 0x%x\n", argv[1], HashSpider( lestr, len )); 

  return 0;
}

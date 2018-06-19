#include <openssl/des.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
      const char *keystring = "需要加密的内容";
      DES_cblock key;
      DES_key_schedule key_schedule;

      //生成一个 key
      DES_string_to_key(keystring, &key);
      if (DES_set_key_checked(&key, &key_schedule) != 0) {
          printf("convert to key_schedule failed.\n");
          return -1;
      }

      //需要加密的字符串
      unsigned char input[] = "this is a text being encrypted by openssl";
      size_t len = (sizeof(input)+7)/8 * 8;
      unsigned char *output = (unsigned char*)malloc(len+1);
      //IV
      DES_cblock ivec;

      //IV设置为0x0000000000000000
      memset((char*)&ivec, 0, sizeof(ivec));

      //加密
      DES_cbc_encrypt(input, output, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT);

      //输出加密以后的内容
      int i;
      for (i = 0; i < len; ++i)
         printf("%02x", output[i]);
      printf("\n");

      memset((char*)&ivec, 0, sizeof(ivec));

      //解密
      DES_cbc_encrypt(output, input, len, &key_schedule, &ivec, 0);

      printf("%s\n", input);

      free(output);

      return EXIT_SUCCESS;
}

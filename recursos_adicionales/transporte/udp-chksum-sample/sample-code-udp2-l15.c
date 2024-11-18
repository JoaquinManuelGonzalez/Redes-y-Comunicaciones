#include <stdint.h>
#include <stdio.h>

// captura: udp2.pcap (l15)

#define MASK1 0xFFFF0000
#define MASK2 0x0000FFFF

/** Little Endian Version Only **/
static uint16_t chksum1(uint16_t sum, const uint16_t *data, uint16_t len)
{
  uint32_t res         = sum;
  uint16_t chksum_val;  

  for(int i=0;i<len;i++)
   {
     res+=data[i]; /* sum in 16bits chunks */
#ifdef CK_DEBUG  // step by step "hand" view
     printf("%04X\n",res);
#endif
     if (res & MASK1) /* Carry */
       {
	 res = res & MASK2; /* Truncate to 16bits */
	 res++; /* Add carry bit */
       }
   }
  chksum_val = ~res; /* Complement1 */
  
  /* Return sum in host byte order */  
  // 0 means chksum disabled, so not complemented - 0000 == FFFF (Ca2)   
  return ((chksum_val == 0) ? 0xFFFF : (chksum_val)); 
}


static uint16_t chksum2(uint16_t sum, const uint8_t *data, uint16_t len, int is_little_endian)
{
  uint16_t t;
  const uint8_t *dataptr;
  const uint8_t *last_byte;

  dataptr = data;
  last_byte = data + len - 1;
  
  while(dataptr < last_byte) {  /* At least two more bytes */
    if (is_little_endian)
      {
	t = (dataptr[1] << 8) + dataptr[0];
      }
    else
      {
	t = (dataptr[0] << 8) + dataptr[1];
      }
    sum += t;
    if(sum < t) {
      sum++;            /* carry */
    }
    dataptr += 2;
  }
  
  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;            /* carry */
    }
  }

  sum=~sum; /* Complement1 */
  /* Return sum in host byte order */  
  // 0 means chksum disabled, so not complemented - 0000 == FFFF (Ca2)   
  return ((sum == 0) ? 0xFFFF : (sum)); 
}

int main()
{
  //uint16_t a[10];
  uint16_t a[12];
  
 //src_ip1  - pseudoheader
  a[0] = 0x0a00;  // 10.0
  //src_ip2 - pseudoheader
  a[1] = 0x020a;  // 2.10
  //dst_ip1 - pseudoheader
  a[2] = 0x0a00;  // 10.0
  //dst_ip2 - pseudoheader
  a[3] = 0x040a; //  4.10
  //proto - pseudoheader
  a[4] = 0x0011; // 17 = UDP
  //src_prt
  a[5] = 0x2328; // 9000
  //dst_prt
  a[6] = 0x0007; // 7
  //len
  a[7] = 0x000d; // 13
  //len_rep - pseudoheader
  a[8] = 0x000d; // 13
  // data_byte0 and data_byte1
  a[9] =  0x5445;
  a[10] = 0x5354;
  a[11] = 0x0a00; // 00 padding

  printf("chksum1=0x%04X\n",chksum1(0x0,a,(sizeof(a)/2)));
  printf("chksum2=0x%04X\n",chksum2(0x0,(uint8_t*)a,sizeof(a),1));
  return 0;
}

//
//  sm4test.m
//  eBaoZhang
//
//  Created by 张飞蓬 on 15/5/18.
//
//

#import "sm4login.h"
#import "sm4.h"
#import "NSString+Base64.h"

@implementation sm4login
-(NSString*)sm4Code:(NSString*)s
{
    
    unsigned char key[16] = {(unsigned char)0x38a,(unsigned char)0xe92,(unsigned char)0x6b4,(unsigned char)0x1af,
        (unsigned char)0x316,(unsigned char)0x13, (unsigned int)0x59, (unsigned int)0xa,
        0x19, (unsigned char)0x3fa,(unsigned char)0xf12,(unsigned char)0x6b4,
        (unsigned char)0x29e,(unsigned char)0x8e3,(unsigned char)0xaeb3,(unsigned char)0x270adf
    };
    
    NSMutableString *buffer = [NSMutableString stringWithString:s];
    
    for (int i = [[buffer dataUsingEncoding:NSUTF8StringEncoding] length] % 16; i < 16; i++)
    {
        [buffer appendString:@"\0"];
    }
    
    NSInteger length = [[buffer dataUsingEncoding:NSUTF8StringEncoding] length];
    
    unsigned char * plaintext = (unsigned char*)[buffer UTF8String];
    unsigned char ciphertext[length];
    
    sm4_context ctx;
    sm4_setkey_enc(&ctx,key);
    
    int g = 0;
    while (g + 16 <= length){
        
        unsigned char cellPlain[16] ;
        for (int i = 0; i < 16; i++)
        {
            cellPlain[i] = plaintext[g + i];
        }
        unsigned char cellCipher[16];
        sm4_crypt_ecb(&ctx,1,16, cellPlain,cellCipher);
        for (int i = 0; i < 16; i++)
        {
            ciphertext[g + i] = cellCipher[i];
        }
        g += 16;
        
    }
    
    NSData *bytes= [NSData dataWithBytes:ciphertext length:length];
    NSString* result = [bytes base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    
    NSLog(@"result:%@",result);
    
    return result;
    
}

//-(NSString*)sm4Code:(NSString*)userName
//{
//    
//    unsigned char key[16] = {(unsigned char)0x38a,(unsigned char)0xe92,(unsigned char)0x6b4,(unsigned char)0x1af,
//        (unsigned char)0x316,(unsigned char)0x13, (unsigned int)0x59, (unsigned int)0xa,
//        0x19, (unsigned char)0x3fa,(unsigned char)0xf12,(unsigned char)0x6b4,
//        (unsigned char)0x29e,(unsigned char)0x8e3,(unsigned char)0xaeb3,(unsigned char)0x270adf
//    };
//    
//    NSString *name = userName;
//    
//    unsigned char input[100];
//    //  unsigned char *input = [name UTF8String];
//    const char* inputName = [name UTF8String];
//    for (int i =0; i<100; i++)
//    {
//        if (i<100&&i<strlen(inputName)) {
//            input[i] =inputName[i];
//        }else
//        {
//            input[i]=0;
//        }
//    }
//    
//    NSLog(@"input====%s",input);
//
//    unsigned char *codeput;
//    unsigned char output[100];
//    for (int i =0; i<100; i++)
//    {
//        if (output[i]==0)
//        {
//            codeput = strlcpy(<#char *#>, <#const char *#>, <#size_t#>)
//            
//        }
//    }
//    sm4_context ctx;
//    unsigned long i;
//    //encrypt standard testing vector
//    sm4_setkey_enc(&ctx,key);
//    sm4_crypt_ecb(&ctx,1,100,input,output);
//    NSLog(@"output=======%s",output);
//   
//    NSData * codeData = [NSData dataWithBytes:output length:strlen(strlen(output))];
//    NSString * ss = [NSString base64StringFromData:codeData length:strlen(output)];
////    NSData * data1 = [NSData dataFromBase64String:@"y6mVwHz2Y8ZBhF0qknxVWg=="];
//    NSLog(@"code========%@",ss);
// 
//    
//    //decrypt testing
//    sm4_setkey_dec(&ctx,key);
//    sm4_crypt_ecb(&ctx,0,16,output,output);
//    //	for(i=0;i<16;i++)
//    //		printf("%02x ", output[i]);
//    //	printf("\n");
//    
//    //decrypt 1M times testing vector based on standards.
//    i = 0;
//    sm4_setkey_enc(&ctx,key);
//    while (i<1000000)
//    {
//        sm4_crypt_ecb(&ctx,1,16,input,input);
//        i++;
//    }
//    //	for(i=0;i<16;i++)
//    //		printf("%02x ", input[i]);
//    //	printf("\n");
//    
//    return 0;
//}

@end

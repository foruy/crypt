/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class Crypt */

#ifndef _Included_Crypt
#define _Included_Crypt

#define BUF_SIZE 2048
#define TAPSERVER "taps0"
#define TAPCLIENT "tapc0"

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     Crypt
 * Method:    openDevice
 * Signature: ()LChan;
 */
JNIEXPORT jobject JNICALL Java_Crypt_openDevice
  (JNIEnv *, jclass);

/*
 * Class:     Crypt
 * Method:    readData
 * Signature: (LChan;)LMessage;
 */
JNIEXPORT jobject JNICALL Java_Crypt_readData
  (JNIEnv *, jclass, jobject);

/*
 * Class:     Crypt
 * Method:    writeData
 * Signature: (LChan;LMessage;)V
 */
JNIEXPORT void JNICALL Java_Crypt_writeData
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     Crypt
 * Method:    closeDevice
 * Signature: (LChan;)V
 */
JNIEXPORT void JNICALL Java_Crypt_closeDevice
  (JNIEnv *, jclass, jobject);

#ifdef __cplusplus
}
#endif
#endif

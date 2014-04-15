#include <ruby.h>
#include "siv.h"

// Convenience constant for unsigned char size
const int SIV_UCHAR_SIZE = sizeof(unsigned char);

// Top-level objects for the native extension
static VALUE siv_rb;
static VALUE siv_rb_cipher;

/* 
 * Initialize an SIV::Cipher object with a key.
 * Performs basic length validation on the key.
 */
static VALUE siv_rb_initialize(VALUE self, VALUE key) {
 
  int keyLen;
  
  // Replace key value with key.to_str
  StringValue(key);
  
  // Get the key length as an int.
  keyLen = RSTRING_LEN(key);
  
  // Make sure key is not empty
  if (keyLen == 0) {
    rb_raise(rb_eArgError, "Key must be non-empty.");
  }
  
  // Make sure key is acceptable size
  if (keyLen * 8 != SIV_256 &&
      keyLen * 8 != SIV_384 &&
      keyLen * 8 != SIV_512) {
    rb_raise(rb_eArgError, "Supported key sizes are 256, 384 and 512 bits.");
  }
  
  // Set key as instance variable
  rb_iv_set(self, "@key", key);
  
  return self;
  
}

/*
 * Get an siv_ctx object for the current instance
 * by fetching the @key instance variable, converting
 * it to a byte array and feeding it into siv_init.
 * Called by siv_rb_encrypt and siv_rb_decrypt.
 *
 * Returns 1 upon success, 0 upon failure.
 */
static int siv_rb_get_ctx(VALUE self, siv_ctx* ctx) {
  
  VALUE key; unsigned char* cKey; int cKeyLen;
  
  // Get the key instance variable
  key = rb_iv_get(self, "@key");
  
  // Convert the key to a byte array
  cKey = (unsigned char*) RSTRING_PTR(key);
  cKeyLen = RSTRING_LEN(key);
  
  // Initialize the context with the key
  if (siv_init(ctx, cKey, cKeyLen * 8) < 0) {
    return 0;
  }
  
  // Return 1 upon successful initialization
  return 1;
  
}

/*
 * Get the associated data as an array of integer lengths
 * and an array of unsigned char arrays representing data.
 */
static int siv_rb_get_associated(VALUE associated, int* cAdLensIn, unsigned char** cAdsIn) {
  
  // Reference to arguments
  int cAdNum; int* cAdLens;
  unsigned char** cAds;
  
  // Values for iterator
  int i; VALUE adElement;
  unsigned char* cAdElement;
  int cAdElementLen;
  
  // Set the references to arguments.
  cAdLens = cAdLensIn; cAds = cAdsIn;
  
  // Get the number of associated data items
  cAdNum = (int) RARRAY_LEN(associated);
  
  // Iterate over each associated data
  for (i = 0; i < cAdNum; i++) {

    // Get an element in the Ruby array
    adElement = rb_ary_entry(associated, (long) i);
    
    // Convert the Ruby string to bytes
    StringValue(adElement);
    cAdElement = (unsigned char*) RSTRING_PTR(adElement);
    cAdElementLen = RSTRING_LEN(adElement);
    
    // Set the element length
    cAdLens[i] = cAdElementLen;
    
    // Set the element data
    if (cAdElementLen > 0) {
    
      cAds[i] = (unsigned char*) malloc(SIV_UCHAR_SIZE * cAdElementLen);
      cAds[i] = cAdElement;
    
    }
    
  }
  
  // Return 1 to indicate success;
  return 1;

}

/*
 * Encrypt a plaintext and some associated data
 */
static VALUE siv_rb_encrypt(VALUE self, VALUE plaintext, VALUE associated) {
  
  // Holds the SIV context object.
  siv_ctx ctx;
  
  // Input plaintext as byte array.
  const unsigned char* cPlaintext;
  
  // Length of the input plaintext.
  int cPlaintextLen;
  
  // Holds the SIV counter object.
  unsigned char cCounter[AES_BLOCK_SIZE];
  
  // Holds the SIV ciphertext object.
  unsigned char* cCiphertext;
  
  // Hold the parsed associated data.
  int cAdNum; int* cAdLens; unsigned char** cAds;
  
  // For concatenation of IV with data.
  unsigned char* cOutput;
  int cOutputLen; int outputInd;
  
  // Get the SIV context based on the instance's key.
  if (!siv_rb_get_ctx(self, &ctx)) {
    rb_raise(rb_eRuntimeError, "Could not get SIV context");
  }
  
  // Replace the plaintext with plaintext.to_str
  StringValue(plaintext);
  
  // Convert the plaintext to a byte array.
  cPlaintext = (const unsigned char*) RSTRING_PTR(plaintext);
  
  // Get the length of the plaintext as an int.
  cPlaintextLen = RSTRING_LEN(plaintext);
  
  cAdNum = (int) RARRAY_LEN(associated);
  cAdLens = (int *) malloc(sizeof(int) * cAdNum);
  cAds = (unsigned char **) malloc(sizeof(unsigned char*) * cAdNum);
  
  // Get the parsed associated data values.
  if (!siv_rb_get_associated(associated, cAdLens, cAds)) {
    rb_raise(rb_eRuntimeError, "Could not get associated data");
  }
  
  // Allocate space for the ciphertext.
  cCiphertext = (unsigned char*) malloc(SIV_UCHAR_SIZE * cPlaintextLen);
  
  // Call siv_encrypt with all parameters.
  if (siv_encrypt( &ctx, cPlaintext, cCiphertext,
                  (const int) cPlaintextLen, cCounter,
                  (const int) cAdNum, cAdLens, cAds) < 0) {
    rb_raise(rb_eRuntimeError, "SIV encryption failed");
  }
  
  // Prepend the IV (counter) to the ciphertext.
  cOutputLen = cPlaintextLen + AES_BLOCK_SIZE;
  cOutput = (unsigned char*) malloc(SIV_UCHAR_SIZE * cOutputLen);
  
  // Iterate through the output to prepend the iv.
  for (outputInd = 0; outputInd < cOutputLen; ++outputInd) {
    cOutput[outputInd] = (outputInd < AES_BLOCK_SIZE) ?
    cCounter[outputInd] : cCiphertext[outputInd - AES_BLOCK_SIZE];
  }
  
  // Free up dynamically allocated memory.
  free(cAdLens); free(cAds); free(cCiphertext);
  
  // Return a new Ruby string with the resulting value.
  return rb_str_new((const char*) cOutput, cOutputLen);
  
}

static VALUE siv_rb_decrypt(VALUE self, VALUE ciphertext, VALUE associated) {
  
  siv_ctx ctx;
  
  // Holds the counter object bytes
  unsigned char cCounter[AES_BLOCK_SIZE];
  
  // Holds the iv + ciphertext bytes
  const unsigned char* cCiphertext;
  int cCiphertextLen;
  
  // Holds the ciphertext-only bytes
  unsigned char* cCiphertextTrunc;
  int j; int cCiphertextTruncLen;
  
  // Receives the plaintext bytes
  const unsigned char* cPlaintext;
  
  // Holds associated-data
  int cAdNum; int* cAdLens;
  unsigned char** cAds;
  
  // Get the SIV context with the key
  if (!siv_rb_get_ctx(self, &ctx)) {
    rb_raise(rb_eRuntimeError, "Could not get SIV context");
  }
  
  // Get the ciphertext bytes and length
  StringValue(ciphertext);
  cCiphertext = (unsigned char*) RSTRING_PTR(ciphertext);
  cCiphertextLen = RSTRING_LEN(ciphertext);
  
  // Truncate the IV (counter) off the ciphertext
  cCiphertextTrunc = (unsigned char*) malloc(
    SIV_UCHAR_SIZE * (cCiphertextLen - AES_BLOCK_SIZE));
  cCiphertextTruncLen = cCiphertextLen - AES_BLOCK_SIZE;
  
  // Iterate through the ciphertext to truncate
  for (j = 0; j < cCiphertextLen; j++) {
    if (j < AES_BLOCK_SIZE) cCounter[j] = cCiphertext[j];
    else cCiphertextTrunc[j - AES_BLOCK_SIZE] = cCiphertext[j];
  }
  
  // Get the number of associated data items in the array.
  cAdNum = (int) RARRAY_LEN(associated);
  cAdLens = (int *) malloc(sizeof(int) * cAdNum);
  cAds = (unsigned char **) malloc(sizeof(unsigned char*) * cAdNum);
  
  // Get the associated data lengths and data arrays
  if (!siv_rb_get_associated(associated, cAdLens, cAds)) {
    rb_raise(rb_eRuntimeError, "Could not get associated data");
  }
	
	// Allocate space to receive the plaintext.
  cPlaintext = (unsigned char*) malloc(SIV_UCHAR_SIZE * cCiphertextTruncLen);
  
  // Decrypt the ciphertext using SIV.
  if (siv_decrypt(&ctx, cCiphertextTrunc, cPlaintext,
      (const int) cCiphertextTruncLen, cCounter,
      (const int) cAdNum, cAdLens, cAds) < 0) {
    rb_raise(rb_eRuntimeError, "SIV decryption failed");
  }
  
  // Free up dynamically allocated memory.
  free(cAdLens); free(cAds); free(cCiphertextTrunc);
  
  // Build and return a Ruby string object with the plaintext
  return rb_str_new((const char*) cPlaintext, cCiphertextTruncLen);
  
}

/*
 * Main wrapper for the SIV Ruby native extension.
 */
void Init_wrapper(void) {
  
  // Define the top-level module
	siv_rb = rb_define_module("SIV");
	
	// Define the cipher class
	siv_rb_cipher = rb_define_class_under(siv_rb, "Cipher", rb_cObject);
	
	// Define the implemented methods.
	rb_define_method(siv_rb_cipher, "initialize", siv_rb_initialize, 1);
	rb_define_method(siv_rb_cipher, "encrypt", siv_rb_encrypt, 2);
	rb_define_method(siv_rb_cipher, "decrypt", siv_rb_decrypt, 2);
	
  return;
	
}

/*
Debug helper method to print byte arrays in hex format.

void print_hex(const char* header, const unsigned char *bytes, int len) {
  
  int i = 0; printf("\n%s (%d): ", header, len);
  for (i = 0; i < len; ++i) printf("%x", bytes[i]);
  printf("\n");
  
}
*/
#ifdef __cplusplus
extern "C" {
#endif

char* GetPublicKeyByPrivateKey(const char* private_key);

char* GetSendUnitJson(const char* private_key, const char* to_pub_key, const char* last_hash, unsigned long long balance_now, unsigned long long amount);

char* GetReceiveUnitJson(const char* private_key, const char* from_hash, unsigned long long from_amount, const char* last_hash, unsigned long long balance_now);


#ifdef __cplusplus
}
#endif

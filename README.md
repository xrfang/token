# token

Simple cryptographic token for golang, based on AES/GCM algorithm. It does not rely on any internal/external storage (i.e. token store), except for revokation of individual token.

## usage

```
//generate token
uid := uint64(123456)
tok := token.New(uid, time.Now().Add(time.Hour))
fmt.Printf("generated token %q for user %d\n", tok, uid)

//verify token
uid, err := token.Verify(tok)
if err !=nil {
    fmt.Println("token verification failed:", err)
} else {
    fmt.Println("token is valid for user", uid)
}

//revoke specified token, implemented by store a token into a "blacklist", 
//a sync.Map, which consumes memory.
token.Revoke(tok)

//revoke all tokens, by mean of reset the AES key.
token.RevokeAll()
```

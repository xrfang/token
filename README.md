# token

Simple cryptographic token for golang.  This token implementation is based on AES/CBC algorithm, 
it does not rely on any internal/external storage (i.e. token store).

## usage

```
//generate token
uid := uint64(123456)
tok := token.New(uid, time.Now().Add(time.Hour), nil)
fmt.Printf("generated token %q for user %d\n", tok, uid)

//verify token
uid, err := token.Verify(tok)
if err !=nil {
    fmt.Println("token verification failed:", err)
} else {
    fmt.Println("token is valid for user", uid)
}
```

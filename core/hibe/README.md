## Dependencies

```cryptography```

## Introduction

1. ```py
    python hibe_core.py setup
    ```
    Master will be created and stored in ```./hie_store/master.json```  
2. ```py
    python hibe_core.py open org
    ```
    ```key.json``` will be created and stored in ```./hie_store/identities/org/```  
3. ```py
    python hibe_core.py delegate ./hie_store/identities/org alice
    ```
    Suppose parents are in ```./hie_store/identities/org```, ```python hie.py delegate ./hie_store/identities/org alice``` will generate alice’s key and store it in ```./hie_store/identities/org_alice/```  
4. ```py
    python hibe_core.py encrypt ./hie_store/identities/org_alice "hello alice" --out alice_ct.json    
    ```
    Anyone in possession of the recipient’s (alice's) identity can encrypt their messages and send via ```python hibe_core.py encrypt ./hie_store/identities/org_alice <"message"> --out alice_ct.json```
5. ```py
    python hibe_core.py decrypt ./hie_store/identities/org_alice alice_ct.json 
    ```
    Anyone with alice's decryption key can decrypt the message and get ```hello alice```.

Helper:   
> ```python hibe_core.py list``` lists all created identities  
> ```python hibe_core.py publish org/alice``` publish as demo

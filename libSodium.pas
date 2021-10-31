unit libSodium;

interface 

  const 
    KEY_SIZE = 32;

  type
    TKey = Array[0..KEY_SIZE-1] of Byte;

  function createPublicKey(privKey: Array of Byte): TKey;
  function createPrivateKey(): TKey;

implementation

  function crypto_scalarmult_curve25519(q:PAnsiChar; const n:PAnsiChar; const p:PAnsiChar):Integer; 
    cdecl; external;

  function crypto_scalarmult_curve25519_base(q:PAnsiChar; const n:PAnsiChar):Integer; 
    cdecl; external;

  procedure randombytes_buf(buf:PAnsiChar; const size: Integer); 
    cdecl; external;


  function createPublicKey(privKey: Array of Byte): TKey;
  begin
    crypto_scalarmult_curve25519_base(@Result, PAnsiChar(@privKey[0]));
  end;

  function createPrivateKey(): TKey;
  begin
    randombytes_buf(@Result,sizeof(TKey));
  end;

end.
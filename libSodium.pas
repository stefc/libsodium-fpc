unit libSodium;

interface 

  const 
    KEY_SIZE = 32;

  type
    TKey = Array[0..KEY_SIZE-1] of Byte;
    ByteArray = Array of Byte;
    
  function createPublicKey(privKey: Array of Byte): TKey;
  function createPrivateKey(): TKey;
  function createPrivateKeyStd(): TKey;
  function calcSharedSecret(a: Array of Byte; b: Array of Byte): TKey;
  function encodeSharedSecret(sharedSecret: array of Byte; nonceprefix: array of Byte): TKey;
  function hashSHA256(data: array of Byte): TKey;
  procedure cryptXSalsa20(var message: array of Byte; const sharedSecret: array of Byte; const nonce: Array of Byte); 
  function encodeXSalsa20(const message: AnsiString; const sharedSecret, nonce: array of Byte): ByteArray; 
  function decodeXSalsa20(const message: Array of Byte; const sharedSecret, nonce: array of Byte): AnsiString; 

implementation

  function crypto_scalarmult_curve25519(q:PAnsiChar; const n:PAnsiChar; const p:PAnsiChar):Integer; 
    cdecl; external;

  function crypto_scalarmult_curve25519_base(q:PAnsiChar; const n:PAnsiChar):Integer; 
    cdecl; external;

  procedure randombytes_buf(buf:PAnsiChar; const size: Integer); 
    cdecl; external;

  function crypto_hash_sha256(output: PAnsiChar; const input: PAnsiChar; inlen: UInt64): Integer;
    cdecl; external; 

  function crypto_core_hsalsa20(output: PAnsiChar; const input: PAnsiChar; const k: PAnsiChar; const c: PAnsiChar): Integer;
    cdecl; external; 

  function crypto_stream_xsalsa20_xor(c: PAnsiChar; const m: PAnsiChar; mlen: UInt64; const n: PAnsiChar; const k: PAnsiChar): Integer;
    cdecl; external;

  function createPublicKey(privKey: Array of Byte): TKey;
  begin
    crypto_scalarmult_curve25519_base(@Result, PAnsiChar(@privKey[0]));
  end;

  function calcSharedSecret(a: Array of Byte; b: Array of Byte): TKey;
  begin
    Fillchar(Result, KEY_SIZE, 0);
    crypto_scalarmult_curve25519(@Result, PAnsiChar(@a[0]), PAnsiChar(@b[0]));
  end;
  
  function createPrivateKey(): TKey;
  begin
    randombytes_buf(@Result,sizeof(TKey));
  end;

  function createPrivateKeyStd() : TKey;
  begin
    Fillchar(Result,KEY_SIZE,chr(42));
    Result[0] := Result[0] and 248;
    Result[31] := (Result[31] and 127) or 64;
  end;

  function calcHSalsa20(input: array of Byte; k: array of Byte; c: Array of Byte): TKey; 
  begin
    Fillchar(Result,KEY_SIZE,0);
    crypto_core_hsalsa20(@Result, PAnsiChar(@input[0]), PAnsiChar(@k[0]), PAnsiChar(@c[0]));
  end;

  function encodeSharedSecret(sharedSecret: array of Byte; nonceprefix: array of Byte): TKey;
  var 
    s  : AnsiString = 'expand 32-byte k';
    Zero, c, FirstKey : TKey;
  begin    
    Fillchar(Zero,KEY_SIZE,0);
    Fillchar(c,KEY_SIZE,0);
    Move(PAnsiChar(s)^, c, Length(s));
    Firstkey := calcHSalsa20(Zero, sharedSecret, c);
    Result := calcHSalsa20(nonceprefix, firstkey, c);
  end;  

  // SHA-256 Hashcode ermitteln
  function hashSHA256(data: array of Byte): TKey;
  begin
    Fillchar(Result,KEY_SIZE,0);
    crypto_hash_sha256(@Result, PAnsiChar(@data[0]), UInt64(Length(data)));
  end;

  // XSalsa20 Symetric Chiper
  procedure cryptXSalsa20(var message: array of Byte; const sharedSecret: array of Byte; const nonce: Array of Byte); 
  begin 
    crypto_stream_xsalsa20_xor(@message, PAnsiChar(@message[0]), UInt64(Length(message)), 
      PAnsiChar(@Nonce[0]), PAnsiChar(@sharedSecret[0]));
  end;

  function encodeXSalsa20( const message: AnsiString; const sharedSecret, nonce: array of Byte): ByteArray; 
  begin
    SetLength(Result, Length(message));
    crypto_stream_xsalsa20_xor(@result[0], PAnsiChar(message), UInt64(Length(message)), 
      PAnsiChar(@Nonce[0]), PAnsiChar(@sharedSecret[0]));
  end;

  function decodeXSalsa20(const message: Array of Byte; const sharedSecret, nonce: array of Byte): AnsiString; 
  begin
    SetLength(Result, Length(message));
    crypto_stream_xsalsa20_xor(@result[1], PAnsiChar(@message[0]), UInt64(Length(message)), 
      PAnsiChar(@Nonce[0]), PAnsiChar(@sharedSecret[0]));
  end;

end.
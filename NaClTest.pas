program NaClTest;

{$linklib libsodium.23.dylib}

// brew install fpc
// or 
// brew upgrade fpc

// brew link --overwrite fpc

// fpc NaClTest -Mobjfpc -FEbin -Fl/usr/local/lib

// mkdir bin
// cd bin
// rm -rf 
// cmake ..

uses yProcs, libSodium;

const 
  // Sender's Key
  aliceSecret : TKey = (
    $77, $07, $6d, $0a, $73, $18, $a5, $7d,
    $3c, $16, $c1, $72, $51, $b2, $66, $45,
    $df, $4c, $2f, $87, $eb, $c0, $99, $2a,
    $b1, $77, $fb, $a5, $1d, $b9, $2c, $2a
    );


  // Receiver's Key
  bobSecret : TKey = (
    $5d, $ab, $08, $7e, $62, $4a, $8a, $4b, 
    $79, $e1, $7f, $8b, $83, $80, $0e, $e6, 
    $6f, $3b, $b1, $29, $26, $18, $b6, $fd, 
    $1c, $2f, $8b, $27, $ff, $88, $e0, $eb);

  // Nonce ist 24 Bytes lang, wobei nur die ersten 16 Bytes in den HSalsa20 gegeben werden
  noncePrefix : array[0..15] of Byte = (
    $69, $69, $6e, $e9, $55, $b6, $2b, $73,
    $cd, $62, $bd, $a8, $75, $fc, $73, $d6);


  // Nonce ist 24 Bytes lang, wobei nur die ersten 16 Bytes in den HSalsa20 gegeben werden
  nonceSuffix : array[0..7] of Byte = (
    $82, $19, $e0, $03, $6b, $7a, $0b, $37);

var 
  privKey, 
  pubAliceKey,
  pubBobKey,
  senderSharedSk,
  receiverSharedSk,
  shared,
  key2 : TKey;

  nonce : array[0..24-1] of Byte;

  //buffer : array[0..4194304-1] of Byte; 
  buffer : array[0..11-1] of Byte; 

  crypted: array of Byte;

  text: AnsiString;

begin
  // Step A: Create Private Key
  privKey := createPrivateKey();
  writeln('A random new private Key:');
  writeln( ToHex( privKey ));
  privKey := createPrivateKeyStd();
  writeln('A new stand private Key:');
  writeln( ToHex( privKey ));

  writeln('Alice''s Priv Key:');
  writeln( ToHex( aliceSecret ));
  writeln('Bob''s Priv Key:');
  writeln( ToHex( bobSecret ));
  writeln;

  // Step B: Create Public Key
  pubAliceKey := createPublicKey(aliceSecret);
  writeln('Alice''s Pub Key:');
  writeln( ToHex( pubAliceKey ));
  // 8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A 

  pubBobKey := createPublicKey(bobSecret);
  writeln('Bob''s Pub Key:');
  writeln( ToHex( pubBobKey ));
  // DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F

  // Step C: Calculate the shared secret between Sender & Receiver
  senderSharedSk := calcSharedSecret(aliceSecret, pubBobKey);
  receiverSharedSk := calcSharedSecret(bobSecret, pubAliceKey);

  writeln('Shared Secret (Alice to Bob)', Chr(9), ToHex(senderSharedSk));
  writeln('Shared Secret (Bob from Alice)', Chr(9), ToHex(receiverSharedSk));

  // Shared Secret between Bob's Public key and Alice's Private key
  shared := senderSharedSk; 

  key2 := encodeSharedSecret(shared, noncePrefix);
  writeln('k2:' + toHex(key2));


  Move(noncePrefix, nonce[0], Length(noncePrefix));
  Move(nonceSuffix, nonce[16], Length(nonceSuffix));
  writeln('Nonce:', toHex(nonce));
  
  // Verschlüsselung
  FillChar(Buffer, Sizeof(Buffer), 0);
  writeln('sha-256 (pre):' + toHex(hashSHA256(buffer)));
  cryptXSalsa20(buffer, shared, nonce);
  writeln('sha-256 (encode):' + toHex(hashSHA256(buffer)));

  // Entschlüsselung
  cryptXSalsa20(buffer, shared, nonce);
  writeln('sha-256 (decode):' + toHex(hashSHA256(buffer)));

  // Message verschlüsseln 

  crypted := encodeXSalsa20('Hallo Welt!', shared, nonce);
  writeln('Encrypted:' + toHex(crypted));

  text := decodeXSalsa20(crypted, shared, nonce);
  writeln('Decrypted:' + text);
  
end.